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

use crate::ZipArchive;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use utils::random::ChaCha20RngExt;

/// # Specification References
/// * [APPNOTE.TXT - PKWARE ZIP File Format](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
/// * [Central Directory File Header (Section 4.3.12)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
/// * [Local File Header (Section 4.3.7)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
/// * [End of Central Directory Record (Section 4.3.16)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
pub(super) fn create_zip(archive: &ZipArchive) -> Vec<u8> {
    let mut zip_data = Vec::new();
    let mut central_directory = Vec::new();
    let mut offset = 0;

    for entry in &archive.entries {
        let (compression_method, mut compressed) = (
            archive.compression.method(),
            archive.compression.compress(&entry.data),
        );

        let crc = crc32(&entry.data);
        let path_bytes = entry.path.as_bytes();

        let (encryption_header, general_flag) =
            protect_data(crc, &mut compressed, archive.password.clone()).unwrap_or((vec![], 0));

        let compressed_size = encryption_header.len() + compressed.len();

        let local_header = create_local_header(
            crc,
            general_flag,
            compression_method,
            entry.modified,
            compressed_size,
            entry.data.len(),
            path_bytes,
        );

        zip_data.extend(&local_header);
        zip_data.extend(&encryption_header);
        zip_data.extend(&compressed);

        let central_header = create_central_header(
            crc,
            general_flag,
            compression_method,
            entry.modified,
            compressed_size,
            entry.data.len(),
            path_bytes,
            offset,
        );

        central_directory.extend(&central_header);
        offset += local_header.len() + compressed_size;
    }

    let central_offset = zip_data.len();
    zip_data.extend(&central_directory);

    let eocd = create_end_of_central_directory(
        archive.entries.len(),
        central_directory.len(),
        central_offset,
        archive.comment.clone(),
    );

    zip_data.extend(eocd);

    zip_data
}

fn protect_data(
    crc: u32,
    payload: &mut Vec<u8>,
    password: Option<Arc<str>>,
) -> Option<(Vec<u8>, u16)> {
    if let Some(password) = password {
        let (mut k0, mut k1, mut k2) = init_keys(&password);
        let header = gen_encryption_header(crc, &mut k0, &mut k1, &mut k2);

        for byte in payload {
            let plain = *byte;
            let cipher = plain ^ decrypt_byte(k2);
            *byte = cipher;
            update_keys(plain, &mut k0, &mut k1, &mut k2);
        }

        Some((header.to_vec(), 0x01))
    } else {
        None
    }
}

macro_rules! extend {
    ($($data:expr),+ $(,)?) => {{
        let mut extended = Vec::new();

        $(
            extended.extend($data);
        )+

        extended
    }};
}

fn create_local_header(
    crc: u32,
    general_flag: u16,
    compression_method: u16,
    modified: (u16, u16),
    compressed_len: usize,
    data_len: usize,
    path: &[u8],
) -> Vec<u8> {
    extend!(
        [0x50, 0x4B, 0x03, 0x04],
        20u16.to_le_bytes(),
        general_flag.to_le_bytes(),
        compression_method.to_le_bytes(),
        modified.0.to_le_bytes(),
        modified.1.to_le_bytes(),
        crc.to_le_bytes(),
        (compressed_len as u32).to_le_bytes(),
        (data_len as u32).to_le_bytes(),
        (path.len() as u16).to_le_bytes(),
        0u16.to_le_bytes(),
        path,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_central_header(
    crc: u32,
    general_flag: u16,
    compression_method: u16,
    modified: (u16, u16),
    compressed_len: usize,
    data_len: usize,
    path: &[u8],
    offset: usize,
) -> Vec<u8> {
    extend!(
        [0x50, 0x4B, 0x01, 0x02],
        20u16.to_le_bytes(),
        20u16.to_le_bytes(),
        general_flag.to_le_bytes(),
        compression_method.to_le_bytes(),
        modified.0.to_le_bytes(),
        modified.1.to_le_bytes(),
        crc.to_le_bytes(),
        (compressed_len as u32).to_le_bytes(),
        (data_len as u32).to_le_bytes(),
        (path.len() as u16).to_le_bytes(),
        0u16.to_le_bytes(),
        0u16.to_le_bytes(),
        0u16.to_le_bytes(),
        0u16.to_le_bytes(),
        [0, 0, 0, 0],
        (offset as u32).to_le_bytes(),
        path
    )
}

fn create_end_of_central_directory(
    entries_len: usize,
    central_size: usize,
    central_offset: usize,
    comment: Option<Arc<str>>,
) -> Vec<u8> {
    let mut vec = extend!(
        [0x50, 0x4B, 0x05, 0x06],
        0u16.to_le_bytes(),
        0u16.to_le_bytes(),
        (entries_len as u16).to_le_bytes(),
        (entries_len as u16).to_le_bytes(),
        (central_size as u32).to_le_bytes(),
        (central_offset as u32).to_le_bytes()
    );

    if let Some(comment) = comment {
        let comment = comment.as_bytes();
        vec.extend(&(comment.len() as u16).to_le_bytes());
        vec.extend(comment);
    } else {
        vec.extend(0u16.to_le_bytes());
    }

    vec
}

// Precomputed CRC32 lookup table for polynomial 0xEDB88320
#[rustfmt::skip]
static CRC32_TABLE: [u32; 256] = [
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x133A11E5, 0x902AFF5F, 0xE710C9C9,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x133A11E5, 0x902AFF5F, 0xE710C9C9,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x133A11E5, 0x902AFF5F, 0xE710C9C9,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x133A11E5, 0x902AFF5F, 0xE710C9C9,
];

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    
    // Use lookup table for faster computation
    for &byte in data {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ (byte as u32)) & 0xFF) as usize];
    }
    
    !crc
}

fn init_keys<S>(password: &S) -> (u32, u32, u32)
where
    S: AsRef<str> + ?Sized,
{
    let mut k0 = 0x12345678;
    let mut k1 = 0x23456789;
    let mut k2 = 0x34567890;

    for b in password.as_ref().bytes() {
        update_keys(b, &mut k0, &mut k1, &mut k2);
    }

    (k0, k1, k2)
}

fn update_keys(byte: u8, k0: &mut u32, k1: &mut u32, k2: &mut u32) {
    *k0 = crc32_byte(*k0, byte);
    *k1 = (*k1).wrapping_add(*k0 & 0xFF);
    *k1 = (*k1).wrapping_mul(134775813).wrapping_add(1);
    *k2 = crc32_byte(*k2, (*k1 >> 24) as u8);
}

fn crc32_byte(crc: u32, b: u8) -> u32 {
    let mut c = crc ^ (b as u32);
    for _ in 0..8 {
        c = if c & 1 != 0 {
            0xEDB88320 ^ (c >> 1)
        } else {
            c >> 1
        };
    }

    c
}

fn decrypt_byte(k2: u32) -> u8 {
    let temp = (k2 & 0xFFFF) | 0x0002;
    ((temp * (temp ^ 1)) >> 8) as u8
}

fn gen_encryption_header(crc: u32, k0: &mut u32, k1: &mut u32, k2: &mut u32) -> [u8; 12] {
    let mut header = [0u8; 12];
    let mut rng = ChaCha20Rng::from_nano_time();

    for i in header.iter_mut().take(11) {
        let plain = rng.next_u32() as u8;
        *i = plain ^ decrypt_byte(*k2);
        update_keys(plain, k0, k1, k2);
    }

    let final_plain = (crc >> 24) as u8;

    header[11] = final_plain ^ decrypt_byte(*k2);
    update_keys(final_plain, k0, k1, k2);

    header
}
