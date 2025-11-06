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

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use spin::RwLock;

/// A simple string interner for frequently used strings
/// Reduces memory usage by storing each unique string only once
pub struct StringInterner {
    strings: RwLock<BTreeSet<Arc<str>>>,
}

impl StringInterner {
    /// Create a new string interner
    pub fn new() -> Self {
        Self {
            strings: RwLock::new(BTreeSet::new()),
        }
    }

    /// Intern a string, returning an Arc<str> reference
    /// If the string already exists, returns the existing reference
    pub fn intern(&self, s: &str) -> Arc<str> {
        let mut strings = self.strings.write();
        
        // Try to find existing string
        if let Some(existing) = strings.get(s) {
            return existing.clone();
        }
        
        // Insert new string
        let arc_str: Arc<str> = Arc::from(s);
        strings.insert(arc_str.clone());
        arc_str
    }

    /// Pre-intern common strings for faster access
    pub fn pre_intern_common(&self, common: &[&str]) {
        let mut strings = self.strings.write();
        for s in common {
            if !strings.contains(*s) {
                strings.insert(Arc::from(*s));
            }
        }
    }
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::new()
    }
}

/// Global string interner for common paths and table names
static GLOBAL_INTERNER: spin::Once<StringInterner> = spin::Once::new();

/// Initialize the global string interner with common strings
pub fn init_global_interner() {
    GLOBAL_INTERNER.call_once(|| {
        let interner = StringInterner::new();
        
        // Pre-intern common SQLite table names
        interner.pre_intern_common(&[
            "Cookies",
            "Logins",
            "history",
            "bookmarks",
            "credit_cards",
            "autofill",
            "downloads",
            "urls",
            "visits",
            "segments",
        ]);
        
        // Pre-intern common path components
        interner.pre_intern_common(&[
            "User Data",
            "Local State",
            "Default",
            "Profile",
            "Login Data",
            "Cookies.txt",
            "Passwords.txt",
            "History.txt",
            "Bookmarks.txt",
            "Network",
            "LocalAppData",
            "AppData",
            "Roaming",
        ]);
        
        interner
    });
}

/// Get the global string interner
pub fn global_interner() -> &'static StringInterner {
    GLOBAL_INTERNER.call_once(StringInterner::new)
}

/// Intern a string using the global interner
pub fn intern_str(s: &str) -> Arc<str> {
    global_interner().intern(s)
}

/// Intern common table names
pub fn intern_table_name(table: &str) -> Arc<str> {
    intern_str(table)
}

/// Intern common path components
pub fn intern_path_component(path: &str) -> Arc<str> {
    intern_str(path)
}
