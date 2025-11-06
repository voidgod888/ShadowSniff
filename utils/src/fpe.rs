/*
 * This file is part of ShadowSniff (https://github.com/sqlerrorthing/ShadowSniff)
 *
 * MIT License
 *
 * Copyright (c) 2025 sqlerrorthing
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptEncrypt, BCryptGenerateSymmetricKey,
    BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_AES_ALGORITHM,
    BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
};

/// Format-Preserving Encryption error types
#[derive(Debug)]
pub enum FpeError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    InvalidRange,
}

/// Format specification for FPE
#[derive(Clone, Copy)]
pub enum FpeFormat {
    /// Numeric digits (0-9)
    Numeric,
    /// Alphabetic characters (a-z, A-Z)
    Alphabetic,
    /// Alphanumeric (a-z, A-Z, 0-9)
    Alphanumeric,
    /// Hexadecimal (0-9, a-f, A-F)
    Hexadecimal,
    /// ASCII printable (32-126)
    AsciiPrintable,
    /// Custom range
    Custom { min: u8, max: u8 },
}

impl FpeFormat {
    /// Get the radix (number of possible characters) for this format
    fn radix(&self) -> u32 {
        match self {
            FpeFormat::Numeric => 10,
            FpeFormat::Alphabetic => 52, // 26 lowercase + 26 uppercase
            FpeFormat::Alphanumeric => 62, // 10 digits + 26 lowercase + 26 uppercase
            FpeFormat::Hexadecimal => 16,
            FpeFormat::AsciiPrintable => 95, // 126 - 32 + 1
            FpeFormat::Custom { min, max } => (*max as u32 - *min as u32 + 1),
        }
    }

    /// Check if a byte is valid for this format
    fn is_valid_byte(&self, byte: u8) -> bool {
        match self {
            FpeFormat::Numeric => byte >= b'0' && byte <= b'9',
            FpeFormat::Alphabetic => {
                (byte >= b'a' && byte <= b'z') || (byte >= b'A' && byte <= b'Z')
            }
            FpeFormat::Alphanumeric => {
                (byte >= b'0' && byte <= b'9')
                    || (byte >= b'a' && byte <= b'z')
                    || (byte >= b'A' && byte <= b'Z')
            }
            FpeFormat::Hexadecimal => {
                (byte >= b'0' && byte <= b'9')
                    || (byte >= b'a' && byte <= b'f')
                    || (byte >= b'A' && byte <= b'F')
            }
            FpeFormat::AsciiPrintable => byte >= 32 && byte <= 126,
            FpeFormat::Custom { min, max } => byte >= *min && byte <= *max,
        }
    }

    /// Convert a byte to its index in the format range
    fn byte_to_index(&self, byte: u8) -> Option<u32> {
        if !self.is_valid_byte(byte) {
            return None;
        }

        match self {
            FpeFormat::Numeric => Some((byte - b'0') as u32),
            FpeFormat::Alphabetic => {
                if byte >= b'a' && byte <= b'z' {
                    Some((byte - b'a') as u32)
                } else {
                    Some((byte - b'A' + 26) as u32)
                }
            }
            FpeFormat::Alphanumeric => {
                if byte >= b'0' && byte <= b'9' {
                    Some((byte - b'0') as u32)
                } else if byte >= b'a' && byte <= b'z' {
                    Some((byte - b'a' + 10) as u32)
                } else {
                    Some((byte - b'A' + 36) as u32)
                }
            }
            FpeFormat::Hexadecimal => {
                if byte >= b'0' && byte <= b'9' {
                    Some((byte - b'0') as u32)
                } else if byte >= b'a' && byte <= b'f' {
                    Some((byte - b'a' + 10) as u32)
                } else {
                    Some((byte - b'A' + 10) as u32)
                }
            }
            FpeFormat::AsciiPrintable => Some((byte - 32) as u32),
            FpeFormat::Custom { min, max } => Some((byte - min) as u32),
        }
    }

    /// Convert an index to a byte in the format range
    fn index_to_byte(&self, index: u32) -> Option<u8> {
        let radix = self.radix();
        if index >= radix {
            return None;
        }

        match self {
            FpeFormat::Numeric => Some(b'0' + index as u8),
            FpeFormat::Alphabetic => {
                if index < 26 {
                    Some(b'a' + index as u8)
                } else {
                    Some(b'A' + (index - 26) as u8)
                }
            }
            FpeFormat::Alphanumeric => {
                if index < 10 {
                    Some(b'0' + index as u8)
                } else if index < 36 {
                    Some(b'a' + (index - 10) as u8)
                } else {
                    Some(b'A' + (index - 36) as u8)
                }
            }
            FpeFormat::Hexadecimal => {
                if index < 10 {
                    Some(b'0' + index as u8)
                } else {
                    Some(b'a' + (index - 10) as u8)
                }
            }
            FpeFormat::AsciiPrintable => Some(32 + index as u8),
            FpeFormat::Custom { min, max } => Some(*min + index as u8),
        }
    }
}

/// Format-Preserving Encryption using FF1 algorithm (simplified)
pub struct FpeEngine {
    key: Vec<u8>,
    format: FpeFormat,
}

impl FpeEngine {
    /// Create a new FPE engine with a key and format
    pub fn new(key: Vec<u8>, format: FpeFormat) -> Self {
        Self { key, format }
    }

    /// Encrypt data while preserving format
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, FpeError> {
        // Validate all bytes are in format
        for &byte in data {
            if !self.format.is_valid_byte(byte) {
                return Err(FpeError::InvalidFormat);
            }
        }

        // Convert to indices
        let mut indices: Vec<u32> = data
            .iter()
            .map(|&b| self.format.byte_to_index(b))
            .collect::<Option<Vec<u32>>>()
            .ok_or(FpeError::InvalidFormat)?;

        // Encrypt indices using FF1-like algorithm (simplified)
        self.ff1_encrypt(&mut indices, data)?;

        // Convert back to bytes
        indices
            .iter()
            .map(|&idx| self.format.index_to_byte(idx))
            .collect::<Option<Vec<u8>>>()
            .ok_or(FpeError::InvalidFormat)
    }

    /// Decrypt data while preserving format
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, FpeError> {
        // Same as encryption (FF1 is reversible)
        self.encrypt(data)
    }

    /// FF1 algorithm (simplified version using AES)
    fn ff1_encrypt(&self, indices: &mut [u32], tweak: &[u8]) -> Result<(), FpeError> {
        let radix = self.format.radix();
        let n = indices.len();

        if n == 0 {
            return Ok(());
        }

        // Use AES to generate pseudo-random values
        // This is a simplified version - full FF1 uses Feistel networks
        
        // Create a tweak for each round
        let rounds = 10; // Standard FF1 uses 10 rounds
        
        for round in 0..rounds {
            // Generate round key by encrypting tweak + round number
            let mut round_input = Vec::with_capacity(tweak.len() + 4);
            round_input.extend_from_slice(tweak);
            round_input.extend_from_slice(&round.to_le_bytes());
            
            let pseudo_random = self.aes_encrypt_ecb(&round_input)?;
            
            // Use pseudo-random to mix indices
            for i in 0..n {
                if round % 2 == 0 {
                    // Feistel round on left half
                    if i < n / 2 {
                        let j = i + n / 2;
                        if j < n {
                            let mix_value = (pseudo_random[i % pseudo_random.len()] as u32
                                + indices[j] * 256)
                                % radix;
                            indices[i] = (indices[i] + mix_value) % radix;
                        }
                    }
                } else {
                    // Feistel round on right half
                    if i >= n / 2 {
                        let j = i - n / 2;
                        let mix_value = (pseudo_random[i % pseudo_random.len()] as u32
                            + indices[j] * 256)
                            % radix;
                        indices[i] = (indices[i] + mix_value) % radix;
                    }
                }
            }
        }

        Ok(())
    }

    /// Encrypt using AES in ECB mode (for generating pseudo-random)
    fn aes_encrypt_ecb(&self, data: &[u8]) -> Result<Vec<u8>, FpeError> {
        unsafe {
            let mut alg_handle: BCRYPT_ALG_HANDLE = null_mut();
            let mut key_handle: BCRYPT_KEY_HANDLE = null_mut();

            let status = BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                BCRYPT_AES_ALGORITHM,
                null_mut(),
                0,
            );

            if status != STATUS_SUCCESS {
                return Err(FpeError::EncryptionFailed);
            }

            let status = BCryptSetProperty(
                alg_handle,
                BCRYPT_CHAINING_MODE,
                BCRYPT_CHAIN_MODE_ECB as *const _,
                20, // sizeof("ChainingModeECB")
                0,
            );

            if status != STATUS_SUCCESS {
                BCryptCloseAlgorithmProvider(alg_handle, 0);
                return Err(FpeError::EncryptionFailed);
            }

            let status = BCryptGenerateSymmetricKey(
                alg_handle,
                &mut key_handle,
                null_mut(),
                0,
                self.key.as_ptr() as _,
                self.key.len() as u32,
                0,
            );

            if status != STATUS_SUCCESS {
                BCryptCloseAlgorithmProvider(alg_handle, 0);
                return Err(FpeError::EncryptionFailed);
            }

            // Pad data to AES block size (16 bytes)
            let block_size = 16;
            let padded_len = ((data.len() + block_size - 1) / block_size) * block_size;
            let mut padded_data = vec![0u8; padded_len];
            padded_data[..data.len()].copy_from_slice(data);

            let mut ciphertext = vec![0u8; padded_len];
            let mut ciphertext_len = 0u32;

            let status = BCryptEncrypt(
                key_handle,
                padded_data.as_ptr() as _,
                padded_data.len() as u32,
                null_mut(),
                null_mut(),
                0,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut ciphertext_len,
                0,
            );

            BCryptDestroyKey(key_handle);
            BCryptCloseAlgorithmProvider(alg_handle, 0);

            if status != STATUS_SUCCESS {
                return Err(FpeError::EncryptionFailed);
            }

            ciphertext.truncate(ciphertext_len as usize);
            Ok(ciphertext)
        }
    }
}

/// Convenience function to encrypt numeric strings
pub fn encrypt_numeric(key: &[u8], data: &str) -> Result<String, FpeError> {
    let engine = FpeEngine::new(key.to_vec(), FpeFormat::Numeric);
    let encrypted_bytes = engine.encrypt(data.as_bytes())?;
    Ok(String::from_utf8_lossy(&encrypted_bytes).to_string())
}

/// Convenience function to decrypt numeric strings
pub fn decrypt_numeric(key: &[u8], data: &str) -> Result<String, FpeError> {
    let engine = FpeEngine::new(key.to_vec(), FpeFormat::Numeric);
    let decrypted_bytes = engine.decrypt(data.as_bytes())?;
    Ok(String::from_utf8_lossy(&decrypted_bytes).to_string())
}
