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

use crate::FileSystemError;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use core::fmt::{Display, Formatter, Write};
use core::iter::once;
use core::ops::{Deref, Div};
use core::ptr::null_mut;
use core::slice::from_raw_parts;
use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_RoamingAppData, FOLDERID_System, SHGetKnownFolderPath,
};
use windows_sys::core::PWSTR;

#[derive(Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct Path {
    inner: Arc<str>,
}

impl From<String> for Path {
    fn from(value: String) -> Self {
        let path = value.replace('/', "\\");
        let mut normalized = String::with_capacity(path.len());

        let mut chars = path.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                normalized.push('\\');
                while let Some(&'\\') = chars.peek() {
                    chars.next();
                }
            } else {
                normalized.push(c)
            }
        }

        Self {
            inner: normalized.into(),
        }
    }
}

impl Path {
    /// Creates a new Path from a string-like value.
    ///
    /// The path is normalized:
    /// - Forward slashes are converted to backslashes
    /// - Consecutive backslashes are collapsed to single backslashes
    ///
    /// # Security Note
    /// This function does not sanitize paths. It's the caller's responsibility
    /// to ensure paths don't contain directory traversal sequences (`..`) or other
    /// dangerous patterns if security is a concern.
    #[inline]
    pub fn new<S>(path: S) -> Self
    where
        S: AsRef<str>,
    {
        // Reuse From<String> normalization logic
        path.as_ref().to_string().into()
    }

    /// Validates that a path doesn't contain directory traversal patterns.
    ///
    /// Returns `true` if the path is safe, `false` if it contains potentially
    /// dangerous patterns like `..` or `//`.
    #[inline]
    pub fn is_safe(&self) -> bool {
        !self.inner.contains("..") && !self.inner.contains("//")
    }

    /// Sanitizes the path by removing directory traversal patterns.
    ///
    /// This method removes `..` sequences and collapses consecutive slashes.
    /// Note: This is a basic sanitization. For production use, consider more
    /// robust path validation depending on your security requirements.
    #[inline]
    pub fn sanitized(&self) -> Self {
        let mut normalized = String::with_capacity(self.inner.len());
        let mut last_char = None;
        
        for c in self.inner.chars() {
            match c {
                '/' => {
                    if last_char != Some('\\') {
                        normalized.push('\\');
                        last_char = Some('\\');
                    }
                }
                '\\' => {
                    normalized.push('\\');
                    last_char = Some('\\');
                }
                _ => {
                    normalized.push(c);
                    last_char = Some(c);
                }
            }
        }
        
        // Remove ".." patterns (basic sanitization)
        while let Some(pos) = normalized.find("..") {
            normalized.replace_range(pos..pos + 2, "");
        }
        
        Self {
            inner: Arc::from(normalized),
        }
    }

    /// Converts this path to an absolute path.
    ///
    /// Returns an error if the current directory cannot be retrieved.
    #[inline]
    pub fn as_absolute_result(&self) -> Result<Path, FileSystemError> {
        let current_dir = get_current_directory()
            .ok_or(FileSystemError::CurrentDirectoryUnavailable)?;

        let trimmed = self.inner.trim_start_matches(['\\', '/'].as_ref());
        // Pre-allocate with known capacity to avoid reallocations
        let capacity = current_dir.len() + 1 + trimmed.len();
        let mut full = String::with_capacity(capacity);
        full.push_str(&current_dir);
        full.push('\\');
        full.push_str(trimmed);

        Ok(Path {
            inner: Arc::from(full),
        })
    }

    /// Converts this path to an absolute path.
    ///
    /// # Panics
    /// Panics if the current directory cannot be retrieved.
    /// Use `as_absolute_result()` to handle errors gracefully.
    #[inline]
    pub fn as_absolute(&self) -> Path {
        self.as_absolute_result().expect("Failed to get current directory - ensure running on Windows with proper permissions")
    }

    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.inner
            .rsplit('\\')
            .next()
            .map(|s| s.rsplit_once('.').map(|(name, _)| name).unwrap_or(s))
    }

    #[inline]
    pub fn fullname(&self) -> Option<&str> {
        self.inner.rsplit('\\').next()
    }

    #[inline]
    pub fn extension(&self) -> Option<&str> {
        self.inner.rsplit('\\').next()?.rsplit_once('.')?.1.into()
    }

    #[inline]
    pub fn name_and_extension(&self) -> Option<(&str, Option<&str>)> {
        let last_component = self.inner.rsplit('\\').next()?;

        match last_component.rsplit_once('.') {
            Some((name, ext)) if !name.is_empty() => Some((name, Some(ext))),
            _ => Some((last_component, None)),
        }
    }

    /// Get the inner string slice directly
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    #[inline]
    pub fn parent(&self) -> Option<Path> {
        if let Some(pos) = self.inner.rfind('\\') {
            if pos == 0 {
                Some(Path {
                    inner: self.inner[..=pos].into(),
                })
            } else {
                Some(Path {
                    inner: self.inner[..pos].into(),
                })
            }
        } else {
            None
        }
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl Deref for Path {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<S> Div<S> for &Path
where
    S: AsRef<str>,
{
    type Output = Path;

    #[inline]
    fn div(self, rhs: S) -> Self::Output {
        let rhs_ref = rhs.as_ref();
        let rhs_normalized = rhs_ref.replace('/', "\\");
        let lhs_len = self.inner.len();
        let needs_sep = !self.inner.ends_with('\\');
        let capacity = lhs_len + rhs_normalized.len() + if needs_sep { 1 } else { 0 };
        let mut new_path = String::with_capacity(capacity);
        
        new_path.push_str(&self.inner);
        if needs_sep {
            new_path.push('\\');
        }
        new_path.push_str(&rhs_normalized);

        Path {
            inner: Arc::from(new_path),
        }
    }
}

impl<S> Div<S> for Path
where
    S: AsRef<str>,
{
    type Output = Path;

    fn div(self, rhs: S) -> Self::Output {
        &self / rhs
    }
}

pub fn get_current_directory() -> Option<Path> {
    let required_size = unsafe { GetCurrentDirectoryW(0, null_mut()) };
    if required_size == 0 {
        return None;
    }

    let mut buffer = vec![0u16; required_size as usize];
    unsafe {
        buffer.set_len(required_size as usize);
    }

    let len = unsafe { GetCurrentDirectoryW(required_size, buffer.as_mut_ptr()) };
    if len == 0 || len > required_size {
        return None;
    }

    unsafe { buffer.set_len(len as usize) };

    Some(Path::new(String::from_utf16(&buffer).ok()?))
}

pub fn get_known_folder_path(folder_id: &windows_sys::core::GUID) -> Option<Path> {
    unsafe {
        let mut path_raw_ptr: PWSTR = null_mut();
        let hr = SHGetKnownFolderPath(folder_id, 0, null_mut(), &mut path_raw_ptr);
        if hr == S_OK {
            let mut len = 0;
            while *path_raw_ptr.add(len) != 0 {
                len += 1;
            }

            let path = String::from_utf16_lossy(from_raw_parts(path_raw_ptr, len));

            CoTaskMemFree(path_raw_ptr as _);
            Some(Path::new(path))
        } else {
            None
        }
    }
}

impl Path {
    /// Gets the system directory path.
    ///
    /// Returns an error if the system directory path cannot be retrieved.
    pub fn system_result() -> Result<Self, FileSystemError> {
        get_known_folder_path(&FOLDERID_System)
            .ok_or(FileSystemError::SystemPathUnavailable)
    }

    /// Gets the system directory path.
    ///
    /// # Panics
    /// Panics if the system directory path cannot be retrieved.
    /// Use `system_result()` to handle errors gracefully.
    #[inline]
    pub fn system() -> Self {
        Self::system_result().expect("Failed to get system directory - ensure running on Windows with proper permissions")
    }

    /// Gets the AppData (roaming) directory path.
    ///
    /// Returns an error if the AppData directory path cannot be retrieved.
    pub fn appdata_result() -> Result<Self, FileSystemError> {
        get_known_folder_path(&FOLDERID_RoamingAppData)
            .ok_or(FileSystemError::SystemPathUnavailable)
    }

    /// Gets the AppData directory path.
    ///
    /// # Panics
    /// Panics if the AppData directory path cannot be retrieved.
    /// Use `appdata_result()` to handle errors gracefully.
    #[inline]
    pub fn appdata() -> Self {
        Self::appdata_result().expect("Failed to get AppData directory - ensure running on Windows with proper permissions")
    }

    /// Gets the LocalAppData directory path.
    ///
    /// Returns an error if the LocalAppData directory path cannot be retrieved.
    pub fn localappdata_result() -> Result<Self, FileSystemError> {
        get_known_folder_path(&FOLDERID_LocalAppData)
            .ok_or(FileSystemError::SystemPathUnavailable)
    }

    /// Gets the LocalAppData directory path.
    ///
    /// # Panics
    /// Panics if the LocalAppData directory path cannot be retrieved.
    /// Use `localappdata_result()` to handle errors gracefully.
    #[inline]
    pub fn localappdata() -> Self {
        Self::localappdata_result().expect("Failed to get LocalAppData directory - ensure running on Windows with proper permissions")
    }

    /// Gets the temporary directory path.
    ///
    /// Returns an error if the LocalAppData directory cannot be retrieved.
    pub fn temp_result() -> Result<Self, FileSystemError> {
        Ok(Self::localappdata_result()? / "Temp")
    }

    /// Gets the temporary directory path.
    ///
    /// # Panics
    /// Panics if the temp directory cannot be retrieved.
    /// Use `temp_result()` to handle errors gracefully.
    #[inline]
    pub fn temp() -> Self {
        Self::temp_result().expect("Failed to get temp directory - ensure running on Windows with proper permissions")
    }

    /// Creates a temporary file path with the given prefix.
    ///
    /// Returns an error if the temp directory cannot be retrieved.
    #[inline]
    pub fn temp_file_result<S>(prefix: S) -> Result<Self, FileSystemError>
    where
        S: AsRef<str>,
    {
        let ms = unsafe { GetTickCount64() };
        // Use format! only once with both values
        let prefix_str = prefix.as_ref();
        let capacity = prefix_str.len() + 16; // 16 chars for hex timestamp
        let mut filename = String::with_capacity(capacity);
        filename.push_str(prefix_str);
        write!(filename, "{ms:x}").unwrap_or(());
        Ok(Self::temp_result()? / filename)
    }

    /// Creates a temporary file path with the given prefix.
    ///
    /// # Panics
    /// Panics if the temp directory cannot be retrieved.
    /// Use `temp_file_result()` to handle errors gracefully.
    #[inline]
    pub fn temp_file<S>(prefix: S) -> Self
    where
        S: AsRef<str>,
    {
        Self::temp_file_result(prefix).expect("Failed to create temp file path - ensure running on Windows with proper permissions")
    }
}

pub trait WideString {
    fn to_wide(&self) -> Vec<u16>;
}

impl WideString for Path {
    fn to_wide(&self) -> Vec<u16> {
        self.encode_utf16().chain(once(0)).collect()
    }
}
