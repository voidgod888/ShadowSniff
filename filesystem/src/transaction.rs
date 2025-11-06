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

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CommitTransaction, CreateFileTransactedW, CreateTransaction, DeleteFileTransactedW,
    GetFileAttributesTransactedW, MoveFileTransactedW, RollbackTransaction,
    SetFileAttributesTransactedW, FILE_ATTRIBUTE_NORMAL, INVALID_FILE_ATTRIBUTES,
};

/// Transactional NTFS transaction handle
pub struct Transaction(HANDLE);

impl Transaction {
    /// Create a new transaction using Kernel Transaction Manager (KTM)
    pub fn new() -> Result<Self, u32> {
        unsafe {
            // Create a new transaction with default settings
            let transaction_handle = CreateTransaction(
                null_mut(), // Default security attributes
                null_mut(), // Generate new transaction ID
                0,          // No special options
                0,          // Default isolation level
                0,          // No isolation flags
                0,          // Default timeout (as u32, not pointer)
                null_mut(), // No description
            );

            if transaction_handle == INVALID_HANDLE_VALUE {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(Self(transaction_handle))
        }
    }

    /// Commit the transaction
    pub fn commit(self) -> Result<(), u32> {
        unsafe {
            if CommitTransaction(self.0) == 0 {
                let error = windows_sys::Win32::Foundation::GetLastError();
                CloseHandle(self.0);
                return Err(error);
            }

            CloseHandle(self.0);
            Ok(())
        }
    }

    /// Rollback the transaction
    pub fn rollback(self) -> Result<(), u32> {
        unsafe {
            if RollbackTransaction(self.0) == 0 {
                let error = windows_sys::Win32::Foundation::GetLastError();
                CloseHandle(self.0);
                return Err(error);
            }

            CloseHandle(self.0);
            Ok(())
        }
    }

    /// Get the raw handle
    pub fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                // If not committed or rolled back, rollback on drop
                RollbackTransaction(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

/// Transactional file operations
pub struct TransactionalFile {
    handle: HANDLE,
    transaction: Transaction,
}

impl TransactionalFile {
    /// Create or open a file within a transaction
    pub fn create(
        transaction: Transaction,
        path: &str,
        desired_access: u32,
        share_mode: u32,
        creation_disposition: u32,
    ) -> Result<Self, u32> {
        unsafe {
            let path_wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

            let handle = CreateFileTransactedW(
                path_wide.as_ptr(),
                desired_access,
                share_mode,
                null_mut(),
                creation_disposition,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
                transaction.handle(),
                null_mut(),
                null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(Self {
                handle,
                transaction,
            })
        }
    }

    /// Get the file handle
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Get the transaction
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

impl Drop for TransactionalFile {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Transactional file system operations wrapper
pub struct TransactionalFs {
    transaction: Transaction,
}

impl TransactionalFs {
    /// Create a new transactional file system context
    pub fn new() -> Result<Self, u32> {
        let transaction = Transaction::new()?;
        Ok(Self { transaction })
    }

    /// Delete a file transactionally
    pub fn delete_file(&self, path: &str) -> Result<(), u32> {
        unsafe {
            let path_wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

            if DeleteFileTransactedW(path_wide.as_ptr(), self.transaction.handle()) == 0 {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(())
        }
    }

    /// Move/rename a file transactionally
    pub fn move_file(&self, from: &str, to: &str) -> Result<(), u32> {
        unsafe {
            let from_wide: Vec<u16> = from.encode_utf16().chain(core::iter::once(0)).collect();
            let to_wide: Vec<u16> = to.encode_utf16().chain(core::iter::once(0)).collect();

            if MoveFileTransactedW(
                from_wide.as_ptr(),
                to_wide.as_ptr(),
                None,
                None,
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_COPY_ALLOWED,
                self.transaction.handle(),
            ) == 0
            {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(())
        }
    }

    /// Set file attributes transactionally
    pub fn set_file_attributes(&self, path: &str, attributes: u32) -> Result<(), u32> {
        unsafe {
            let path_wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

            if SetFileAttributesTransactedW(
                path_wide.as_ptr(),
                attributes,
                self.transaction.handle(),
            ) == 0
            {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(())
        }
    }

    /// Get file attributes transactionally
    pub fn get_file_attributes(&self, path: &str) -> Result<u32, u32> {
        unsafe {
            let path_wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

            let attrs = GetFileAttributesTransactedW(
                path_wide.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::GetFileExInfoStandard,
                null_mut(),
                self.transaction.handle(),
            );

            if attrs == INVALID_FILE_ATTRIBUTES {
                return Err(windows_sys::Win32::Foundation::GetLastError());
            }

            Ok(attrs as u32)
        }
    }

    /// Commit all transactional operations
    pub fn commit(self) -> Result<(), u32> {
        self.transaction.commit()
    }

    /// Rollback all transactional operations
    pub fn rollback(self) -> Result<(), u32> {
        self.transaction.rollback()
    }
}

