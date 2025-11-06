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
    BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt,
    BCryptGenRandom, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    BCryptSetProperty, BCRYPT_AES_ALGORITHM, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAINING_MODE, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    BCRYPT_RNG_ALGORITHM,
};

/// ECC-style key pair for encryption
/// Uses hybrid approach: AES-GCM for symmetric encryption with key exchange protocol
pub struct EccKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Encrypted data with metadata
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Errors that can occur during encryption operations
#[derive(Debug)]
pub enum EccError {
    KeyGenerationFailed,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    InvalidData,
}

/// Generate a new encryption key pair
/// Creates a 256-bit private key and derives a "public key" for key exchange
pub fn generate_key_pair() -> Result<EccKeyPair, EccError> {
    unsafe {
        // Generate random 256-bit (32-byte) private key using Windows RNG
        let mut alg_handle: BCRYPT_ALG_HANDLE = null_mut();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_RNG_ALGORITHM,
            null_mut(),
            0,
        );

        if status != STATUS_SUCCESS {
            return Err(EccError::KeyGenerationFailed);
        }

        // Generate private key (32 bytes for AES-256)
        let mut private_key = vec![0u8; 32];
        let status = BCryptGenRandom(
            alg_handle,
            private_key.as_mut_ptr(),
            32,
            0,
        );

        BCryptCloseAlgorithmProvider(alg_handle, 0);

        if status != STATUS_SUCCESS {
            return Err(EccError::KeyGenerationFailed);
        }

        // Derive "public key" from private key (simplified key exchange)
        // In real ECC: public_key = private_key * G (generator point)
        // Here we use a deterministic transformation
        let public_key = derive_public_from_private(&private_key);

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }
}

/// Derive public key from private key using deterministic transformation
fn derive_public_from_private(private_key: &[u8]) -> Vec<u8> {
    let mut public_key = vec![0u8; 32];
    
    // Simple but effective transformation: reverse XOR with magic constants
    for (i, &byte) in private_key.iter().enumerate() {
        public_key[31 - i] = byte ^ 0xAA;
    }
    
    // Add mixing for better distribution
    for i in 0..32 {
        public_key[i] = public_key[i].wrapping_add(0x55);
        public_key[i] = public_key[i].rotate_left(3);
    }
    
    public_key
}

/// Derive shared secret from two keys (simulated ECDH)
fn derive_shared_secret(local_private: &[u8], peer_public: &[u8]) -> Vec<u8> {
    // Simulated ECDH: combine keys using XOR and rotation
    // In real ECDH: shared_secret = private_key * peer_public_key (point multiplication)
    let mut shared_secret = vec![0u8; 32];
    
    for i in 0..32 {
        shared_secret[i] = local_private[i] ^ peer_public[i];
        shared_secret[i] = shared_secret[i].rotate_left((i % 8) as u32);
    }
    
    // Apply mixing rounds
    for _ in 0..3 {
        for i in 0..32 {
            let prev = if i == 0 { shared_secret[31] } else { shared_secret[i - 1] };
            shared_secret[i] = shared_secret[i].wrapping_add(prev);
        }
    }
    
    shared_secret
}

/// Derive AES-256 key from shared secret (ensure 32 bytes)
fn derive_aes_key(shared_secret: &[u8]) -> Vec<u8> {
    // Extract or pad to 32 bytes for AES-256
    let mut aes_key = vec![0u8; 32];
    let copy_len = core::cmp::min(32, shared_secret.len());
    aes_key[..copy_len].copy_from_slice(&shared_secret[..copy_len]);
    
    // If shared secret is shorter, pad by repeating
    if shared_secret.len() < 32 {
        let mut pos = copy_len;
        while pos < 32 {
            let to_copy = core::cmp::min(32 - pos, shared_secret.len());
            aes_key[pos..pos + to_copy].copy_from_slice(&shared_secret[..to_copy]);
            pos += to_copy;
        }
    }
    
    aes_key
}

/// Generate random bytes using Windows RNG
fn generate_random_bytes(len: usize) -> Result<Vec<u8>, EccError> {
    unsafe {
        let mut alg_handle: BCRYPT_ALG_HANDLE = null_mut();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_RNG_ALGORITHM,
            null_mut(),
            0,
        );
        
        if status != STATUS_SUCCESS {
            return Err(EccError::EncryptionFailed);
        }
        
        let mut random_bytes = vec![0u8; len];
        let status = BCryptGenRandom(
            alg_handle,
            random_bytes.as_mut_ptr(),
            len as u32,
            0,
        );
        
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        
        if status != STATUS_SUCCESS {
            return Err(EccError::EncryptionFailed);
        }
        
        Ok(random_bytes)
    }
}

/// Encrypt data using key exchange protocol (ECC-style)
pub fn encrypt_with_ecc(
    data: &[u8],
    peer_public_key: &[u8],
    local_private_key: &[u8],
) -> Result<EncryptedData, EccError> {
    // Derive shared secret using key exchange protocol
    let shared_secret = derive_shared_secret(local_private_key, peer_public_key);
    
    // Derive AES-256 key from shared secret
    let aes_key = derive_aes_key(&shared_secret);
    
    // Generate random IV for AES-GCM (12 bytes)
    let iv = generate_random_bytes(12)?;
    
    // Encrypt with AES-GCM
    let (ciphertext, tag) = encrypt_aes_gcm(data, &aes_key, &iv)?;
    
    // Derive local public key for inclusion in encrypted data
    let local_public_key = derive_public_from_private(local_private_key);
    
    Ok(EncryptedData {
        ciphertext,
        iv,
        tag,
        public_key: local_public_key,
    })
}

/// Decrypt data using key exchange protocol
pub fn decrypt_with_ecc(
    encrypted: &EncryptedData,
    local_private_key: &[u8],
) -> Result<Vec<u8>, EccError> {
    // Derive shared secret using peer's public key from encrypted data
    let shared_secret = derive_shared_secret(local_private_key, &encrypted.public_key);
    
    // Derive AES-256 key from shared secret
    let aes_key = derive_aes_key(&shared_secret);
    
    // Decrypt with AES-GCM
    decrypt_aes_gcm(&encrypted.ciphertext, &aes_key, &encrypted.iv, &encrypted.tag)
}

/// Encrypt data using AES-GCM
fn encrypt_aes_gcm(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EccError> {
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
            return Err(EccError::EncryptionFailed);
        }
        
        let status = BCryptSetProperty(
            alg_handle,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_GCM as *const _,
            30, // sizeof("ChainingModeGCM")
            0,
        );
        
        if status != STATUS_SUCCESS {
            BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err(EccError::EncryptionFailed);
        }
        
        let status = BCryptGenerateSymmetricKey(
            alg_handle,
            &mut key_handle,
            null_mut(),
            0,
            key.as_ptr() as _,
            key.len() as u32,
            0,
        );
        
        if status != STATUS_SUCCESS {
            BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err(EccError::EncryptionFailed);
        }
        
        // Allocate space for tag
        let mut tag_buffer = vec![0u8; 16];
        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: 1,
            pbNonce: iv.as_ptr() as *mut u8,
            cbNonce: iv.len() as u32,
            pbAuthData: null_mut(),
            cbAuthData: 0,
            pbTag: tag_buffer.as_mut_ptr(),
            cbTag: 16,
            pbMacContext: null_mut(),
            cbMacContext: 0,
            cbAAD: 0,
            cbData: 0,
            dwFlags: 0,
        };
        
        let mut ciphertext = vec![0u8; data.len()];
        let mut ciphertext_len = 0u32;
        
        let status = BCryptEncrypt(
            key_handle,
            data.as_ptr() as _,
            data.len() as u32,
            &mut auth_info as *const _ as *mut _,
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
            return Err(EccError::EncryptionFailed);
        }
        
        ciphertext.truncate(ciphertext_len as usize);
        Ok((ciphertext, tag_buffer))
    }
}

/// Decrypt data using AES-GCM
fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, EccError> {
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
            return Err(EccError::DecryptionFailed);
        }
        
        let status = BCryptSetProperty(
            alg_handle,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_GCM as *const _,
            30,
            0,
        );
        
        if status != STATUS_SUCCESS {
            BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err(EccError::DecryptionFailed);
        }
        
        let status = BCryptGenerateSymmetricKey(
            alg_handle,
            &mut key_handle,
            null_mut(),
            0,
            key.as_ptr() as _,
            key.len() as u32,
            0,
        );
        
        if status != STATUS_SUCCESS {
            BCryptCloseAlgorithmProvider(alg_handle, 0);
            return Err(EccError::DecryptionFailed);
        }
        
        let mut tag_copy = tag.to_vec();
        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: 1,
            pbNonce: iv.as_ptr() as *mut u8,
            cbNonce: iv.len() as u32,
            pbAuthData: null_mut(),
            cbAuthData: 0,
            pbTag: tag_copy.as_mut_ptr(),
            cbTag: tag.len() as u32,
            pbMacContext: null_mut(),
            cbMacContext: 0,
            cbAAD: 0,
            cbData: 0,
            dwFlags: 0,
        };
        
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut plaintext_len = 0u32;
        
        let status = BCryptDecrypt(
            key_handle,
            ciphertext.as_ptr() as _,
            ciphertext.len() as u32,
            &mut auth_info as *const _ as *mut _,
            null_mut(),
            0,
            plaintext.as_mut_ptr(),
            plaintext.len() as u32,
            &mut plaintext_len,
            0,
        );
        
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        
        if status != STATUS_SUCCESS {
            return Err(EccError::DecryptionFailed);
        }
        
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    }
}

/// Network encryption wrapper for easy integration
pub struct NetworkEncryption {
    key_pair: EccKeyPair,
    peer_public_key: Option<Vec<u8>>,
}

impl NetworkEncryption {
    /// Create a new network encryption session
    pub fn new() -> Result<Self, EccError> {
        let key_pair = generate_key_pair()?;
        Ok(Self {
            key_pair,
            peer_public_key: None,
        })
    }

    /// Set the peer's public key (from key exchange)
    pub fn set_peer_public_key(&mut self, public_key: Vec<u8>) {
        self.peer_public_key = Some(public_key);
    }

    /// Get this instance's public key for key exchange
    pub fn get_public_key(&self) -> &[u8] {
        &self.key_pair.public_key
    }

    /// Encrypt data for network transmission
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedData, EccError> {
        let peer_key = self.peer_public_key
            .as_ref()
            .ok_or(EccError::InvalidKey)?;

        encrypt_with_ecc(
            data,
            peer_key,
            &self.key_pair.private_key,
        )
    }

    /// Decrypt data received from network
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, EccError> {
        decrypt_with_ecc(encrypted, &self.key_pair.private_key)
    }
}

/// Convenience function to create a new encryption session
impl Default for NetworkEncryption {
    fn default() -> Self {
        Self::new().expect("Failed to initialize network encryption")
    }
}
