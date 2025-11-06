# FPE, VEH, and Transactional NTFS Implementation

## Overview

This document describes the implementation of three advanced Windows features:
1. **Format-Preserving Encryption (FPE)** - Encrypts data while preserving its format
2. **Vectored Exception Handling (VEH)** - Advanced exception handling mechanism
3. **Transactional NTFS (TxF)** - Atomic file system operations

## 1. Format-Preserving Encryption (FPE)

### Location: `utils/src/fpe.rs`

Format-Preserving Encryption allows encryption of data while maintaining its original format, making it useful for encrypting structured data like credit card numbers, SSNs, etc.

### Features:
- **Multiple Format Support**:
  - Numeric (0-9)
  - Alphabetic (a-z, A-Z)
  - Alphanumeric (a-z, A-Z, 0-9)
  - Hexadecimal (0-9, a-f, A-F)
  - ASCII Printable (32-126)
  - Custom ranges

- **FF1 Algorithm**: Simplified implementation using AES for pseudo-random generation
- **Format Preservation**: Encrypted output maintains same character set and length

### Usage Example:
```rust
use utils::fpe::{FpeEngine, FpeFormat, encrypt_numeric};

// Create FPE engine
let key = vec![0u8; 32]; // 32-byte AES key
let engine = FpeEngine::new(key, FpeFormat::Numeric);

// Encrypt numeric string
let plaintext = b"1234567890";
let encrypted = engine.encrypt(plaintext)?; // Returns same format (numeric)

// Or use convenience function
let encrypted_str = encrypt_numeric(&key, "1234567890")?;
let decrypted_str = decrypt_numeric(&key, &encrypted_str)?;
```

### Implementation Details:
- Uses AES-ECB for generating pseudo-random values
- Implements simplified Feistel network for FF1
- Supports custom radix (character set size)
- Validates input format before encryption

## 2. Vectored Exception Handling (VEH)

### Location: `utils/src/veh.rs`

Vectored Exception Handlers are a Windows mechanism for handling exceptions before they reach standard exception handlers. They can be used for debugging, protection, and control flow manipulation.

### Features:
- **Handler Registration**: Add exception handlers that run before standard handlers
- **Exception Types**: Supports all Windows exception types
- **Memory Guards**: Protect specific memory regions
- **Access Violation Handling**: Monitor and handle memory access violations
- **Breakpoint Handling**: Handle software breakpoints

### Usage Example:
```rust
use utils::veh::{VectoredExceptionHandler, ExceptionAction, create_access_violation_handler};
use alloc::sync::Arc;

// Create an exception handler
let handler_fn = Arc::new(|exception, context| {
    if exception.ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
        // Handle access violation
        println!("Access violation occurred!");
        ExceptionAction::ExecuteHandler
    } else {
        ExceptionAction::ContinueSearch
    }
});

// Register handler (first = true means it runs before other handlers)
let veh = VectoredExceptionHandler::new(true, handler_fn)?;

// Memory guard example
let protected_address = allocate_memory();
let guard = MemoryGuard::new(
    protected_address,
    4096, // Size
    Arc::new(|addr| {
        println!("Access to protected memory at {:p}!", addr);
        ExceptionAction::ContinueSearch
    }),
)?;
```

### Implementation Details:
- Uses Windows `AddVectoredExceptionHandler` API
- Maintains global handler registry
- Thread-safe handler storage using `spin::Mutex`
- Supports handler chaining and early termination

## 3. Transactional NTFS (TxF)

### Location: `filesystem/src/transaction.rs`

Transactional NTFS provides atomic file system operations using Kernel Transaction Manager (KTM). All operations within a transaction either all succeed or all fail.

### Features:
- **Atomic Operations**: Multiple file operations succeed or fail together
- **Transaction Management**: Create, commit, or rollback transactions
- **Transactional File Operations**:
  - Create/Open files
  - Delete files
  - Move/Rename files
  - Set file attributes
  - Get file attributes

### Usage Example:
```rust
use filesystem::transaction::{TransactionalFs, Transaction};

// Create transactional file system context
let tx_fs = TransactionalFs::new()?;

// Perform multiple operations atomically
tx_fs.delete_file("old_file.txt")?;
tx_fs.move_file("source.txt", "destination.txt")?;
tx_fs.set_file_attributes("config.ini", FILE_ATTRIBUTE_NORMAL)?;

// Commit all operations (or they all rollback on drop)
tx_fs.commit()?;

// Or create individual transaction
let transaction = Transaction::new()?;
// ... perform operations ...
transaction.commit()?; // or rollback()
```

### Implementation Details:
- Uses Windows KTM (`ktmw32.dll`)
- Links to `CreateTransaction`, `CommitTransaction`, `RollbackTransaction` APIs
- Implements transactional file operations using `*TransactedW` APIs
- Automatic rollback on drop if not committed

### Transactional File Operations:
- `CreateFileTransactedW`: Create or open files within transaction
- `DeleteFileTransactedW`: Delete files transactionally
- `MoveFileTransactedW`: Move/rename files transactionally
- `SetFileAttributesTransactedW`: Set attributes transactionally
- `GetFileAttributesTransactedW`: Get attributes transactionally

## Integration Notes

### Dependencies:
- **FPE**: Requires `utils` crate with `windows-sys` for AES operations
- **VEH**: Requires `spin` crate for thread-safe storage
- **TxF**: Requires Windows KTM (`ktmw32.dll`)

### Windows Requirements:
- **FPE**: Windows 7+ (BCrypt APIs)
- **VEH**: Windows XP+ (always available)
- **TxF**: Windows Vista+ (NTFS 3.1+ required)

## Error Handling

### FPE Errors:
```rust
pub enum FpeError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    InvalidRange,
}
```

### VEH Errors:
- Returns `Result<(), ()>` for handler registration
- Handler functions return `ExceptionAction` enum

### TxF Errors:
- Returns `Result<T, u32>` where `u32` is Windows error code
- Use `GetLastError()` to retrieve detailed error information

## Security Considerations

### FPE:
- ⚠️ Simplified FF1 implementation - use full FF1/FF3-1 for production
- Keys should be properly managed and stored securely
- Consider using key derivation functions

### VEH:
- ⚠️ Exception handlers run with high privileges
- Be careful with exception handling to avoid security issues
- Memory guards should validate access patterns

### TxF:
- ⚠️ Requires NTFS file system
- Transactions have timeouts (default is implementation-defined)
- Large transactions may impact performance

## Performance Notes

- **FPE**: Slower than standard encryption due to format preservation overhead
- **VEH**: Minimal overhead when no exceptions occur
- **TxF**: Some overhead due to transaction logging, but provides ACID guarantees

---

*Last Updated: 2025*
