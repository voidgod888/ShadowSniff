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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use spin::Mutex;
use windows_sys::Win32::Foundation::{EXCEPTION_POINTERS, EXCEPTION_RECORD, LONG};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    RemoveVectoredExceptionHandler, EXCEPTION_EXECUTE_HANDLER, PVECTORED_EXCEPTION_HANDLER,
};

// Global exception handler registry
static EXCEPTION_HANDLERS: Mutex<Vec<Arc<dyn ExceptionHandlerFn>>> = Mutex::new(Vec::new());

/// Exception handler function type
pub type ExceptionHandlerFn = dyn Fn(&EXCEPTION_RECORD, *mut c_void) -> ExceptionAction + Send + Sync;

/// Exception action to take
#[derive(Debug, Clone, Copy)]
pub enum ExceptionAction {
    /// Continue execution at the exception point
    Continue,
    /// Continue searching for other handlers
    ContinueSearch,
    /// Execute handler and stop searching
    ExecuteHandler,
}

/// Vectored Exception Handler wrapper
pub struct VectoredExceptionHandler {
    handler: Arc<dyn ExceptionHandlerFn>,
    handle: *mut c_void,
}

impl VectoredExceptionHandler {
    /// Create a new vectored exception handler
    /// 
    /// # Arguments
    /// * `first` - If true, handler is called first (before all handlers). 
    ///   If false, handler is called last (after all handlers).
    /// * `handler` - Function to call when exception occurs
    pub fn new(first: bool, handler: Arc<dyn ExceptionHandlerFn>) -> Result<Self, ()> {
        unsafe {
            let handler_ptr = Box::into_raw(Box::new(handler.clone())) as *mut c_void;

            // Create the Windows exception handler function
            extern "system" fn wrapper(
                exception_info: *mut EXCEPTION_POINTERS,
            ) -> LONG {
                if exception_info.is_null() {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                let exception_pointers = &*exception_info;
                let exception_record = exception_pointers.ExceptionRecord;
                
                if exception_record.is_null() {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                let exception = &*exception_record;
                
                // Get the user handler from context (stored in handler pointer)
                // This is a simplified approach - in production, use a thread-local or global registry
                let action = handle_exception(exception, exception_pointers.ContextRecord);
                
                match action {
                    ExceptionAction::Continue => EXCEPTION_CONTINUE_EXECUTION,
                    ExceptionAction::ContinueSearch => EXCEPTION_CONTINUE_SEARCH,
                    ExceptionAction::ExecuteHandler => EXCEPTION_EXECUTE_HANDLER,
                }
            }

            let handle = AddVectoredExceptionHandler(
                if first { 1 } else { 0 },
                Some(wrapper as PVECTORED_EXCEPTION_HANDLER),
            );

            if handle.is_null() {
                return Err(());
            }

            Ok(Self {
                handler,
                handle,
            })
        }
    }

    /// Get the Windows handle for this handler
    pub fn handle(&self) -> *mut c_void {
        self.handle
    }
}

impl Drop for VectoredExceptionHandler {
    fn drop(&mut self) {
        unsafe {
            RemoveVectoredExceptionHandler(self.handle);
        }
    }
}


/// Register a global exception handler
pub fn register_exception_handler(handler: Arc<dyn ExceptionHandlerFn>) -> Result<(), ()> {
    let mut handlers = EXCEPTION_HANDLERS.lock();
    handlers.push(handler);
    Ok(())
}

/// Handle exception using registered handlers
fn handle_exception(
    exception: &EXCEPTION_RECORD,
    context: *mut c_void,
) -> ExceptionAction {
    let handlers = EXCEPTION_HANDLERS.lock();
    
    for handler in handlers.iter() {
        let action = handler(exception, context);
        match action {
            ExceptionAction::ExecuteHandler => return action,
            ExceptionAction::Continue => return action,
            ExceptionAction::ContinueSearch => continue,
        }
    }
    
    ExceptionAction::ContinueSearch
}

/// Common exception handler for access violations
pub fn create_access_violation_handler(
    target_address: *mut c_void,
    on_access: Arc<dyn Fn(*mut c_void) -> ExceptionAction + Send + Sync>,
) -> Arc<dyn ExceptionHandlerFn> {
    Arc::new(move |exception: &EXCEPTION_RECORD, _context: *mut c_void| {
        // Check if this is an access violation
        if exception.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION {
            if let Some(info) = exception.ExceptionInformation.as_ref() {
                let accessed_address = info[1] as *mut c_void;
                
                // Check if this is our target address
                if accessed_address == target_address {
                    return on_access(target_address);
                }
            }
        }
        
        ExceptionAction::ContinueSearch
    })
}

/// Common exception handler for breakpoints
pub fn create_breakpoint_handler(
    on_breakpoint: Arc<dyn Fn(*mut c_void) -> ExceptionAction + Send + Sync>,
) -> Arc<dyn ExceptionHandlerFn> {
    Arc::new(move |exception: &EXCEPTION_RECORD, context: *mut c_void| {
        // Check if this is a breakpoint exception
        if exception.ExceptionCode == windows_sys::Win32::Foundation::EXCEPTION_BREAKPOINT {
            return on_breakpoint(context);
        }
        
        ExceptionAction::ContinueSearch
    })
}

/// Memory access protection handler
pub struct MemoryGuard {
    handler: Option<VectoredExceptionHandler>,
    address: *mut c_void,
    size: usize,
}

impl MemoryGuard {
    /// Create a memory guard that watches for access violations
    pub fn new(
        address: *mut c_void,
        size: usize,
        on_access: Arc<dyn Fn(*mut c_void) -> ExceptionAction + Send + Sync>,
    ) -> Result<Self, ()> {
        let handler_fn = create_access_violation_handler(address, on_access);
        let handler = VectoredExceptionHandler::new(true, handler_fn)?;

        Ok(Self {
            handler: Some(handler),
            address,
            size,
        })
    }

    /// Get the protected address
    pub fn address(&self) -> *mut c_void {
        self.address
    }

    /// Get the protected size
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        // Handler is automatically removed via Drop
        self.handler = None;
    }
}
