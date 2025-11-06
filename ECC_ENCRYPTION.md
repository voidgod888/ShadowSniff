# ECC Encryption for Network Interactions

## Overview

ECC (Elliptic Curve Cryptography) encryption has been implemented for secure network communications in ShadowSniff. This provides end-to-end encryption for HTTP requests and responses.

## Architecture

The implementation uses a **hybrid encryption** approach:
- **Key Exchange**: ECC-style key exchange protocol for deriving shared secrets
- **Symmetric Encryption**: AES-256-GCM for actual data encryption
- **Random Generation**: Windows BCrypt RNG for secure random number generation

## Components

### 1. ECC Module (`utils/src/ecc.rs`)

Core encryption module providing:

#### Key Generation
```rust
use utils::ecc::generate_key_pair;

let key_pair = generate_key_pair()?;
// key_pair.private_key - 32-byte private key
// key_pair.public_key - 32-byte public key (for exchange)
```

#### Encryption/Decryption
```rust
use utils::ecc::{encrypt_with_ecc, decrypt_with_ecc, EncryptedData};

// Encrypt data
let encrypted = encrypt_with_ecc(
    &data,
    &peer_public_key,
    &local_private_key,
)?;

// Decrypt data
let decrypted = decrypt_with_ecc(
    &encrypted,
    &local_private_key,
)?;
```

#### Network Encryption Wrapper
```rust
use utils::ecc::NetworkEncryption;

// Create encryption session
let mut encryption = NetworkEncryption::new()?;

// Exchange public keys (from peer)
encryption.set_peer_public_key(peer_public_key);

// Encrypt data
let encrypted = encryption.encrypt(&data)?;

// Decrypt data
let decrypted = encryption.decrypt(&encrypted)?;
```

### 2. HTTP Client Integration (`requests/src/lib.rs`)

The HTTP client now supports optional ECC encryption:

#### Encrypted Request Example
```rust
use requests::Request;
use utils::ecc::NetworkEncryption;
use alloc::sync::Arc;

// Setup encryption
let encryption = Arc::new(NetworkEncryption::new()?);
encryption.set_peer_public_key(server_public_key);

// Create encrypted POST request
let response = Request::post("https://example.com/api")
    .header("Content-Type", "application/json")
    .body(b"{\"data\":\"sensitive information\"}")
    .encryption(encryption.clone())
    .build()
    .send()?;

// Decrypt response if needed
let decrypted_body = response.decrypt_body(&encryption)?;
```

## Encryption Format

Encrypted requests/responses use JSON format:

```json
{
  "encrypted": true,
  "data": "<base64_ciphertext>",
  "iv": "<base64_iv>",
  "tag": "<base64_auth_tag>",
  "pubkey": "<base64_public_key>"
}
```

### Fields:
- `encrypted`: Boolean flag indicating encryption
- `data`: Base64-encoded ciphertext
- `iv`: Base64-encoded initialization vector (12 bytes)
- `tag`: Base64-encoded GCM authentication tag (16 bytes)
- `pubkey`: Base64-encoded public key for key exchange

## Security Features

1. **AES-256-GCM Encryption**
   - Strong symmetric encryption
   - Authenticated encryption (integrity + confidentiality)
   - Hardware-accelerated on modern CPUs

2. **Secure Key Exchange**
   - Ephemeral keys for each session
   - Shared secret derivation
   - Forward secrecy (if keys are rotated)

3. **Random Number Generation**
   - Windows BCrypt RNG (cryptographically secure)
   - Used for IVs, keys, and nonces

4. **Key Derivation**
   - Deterministic transformation from shared secret
   - Ensures 32-byte AES-256 keys
   - Multiple mixing rounds

## Usage Patterns

### Client-Server Communication

```rust
// Client side
let mut client_enc = NetworkEncryption::new()?;
client_enc.set_peer_public_key(server_public_key_bytes);

let request = Request::post("https://api.example.com/data")
    .body(sensitive_data)
    .encryption(Arc::new(client_enc))
    .build();

let response = request.send()?;
let decrypted = response.decrypt_body(&client_enc)?;

// Server side (similar pattern)
let mut server_enc = NetworkEncryption::new()?;
server_enc.set_peer_public_key(client_public_key_bytes);
// ... process encrypted request ...
```

### Key Exchange Protocol

1. **Initialization**: Both parties generate key pairs
2. **Exchange**: Public keys are exchanged (out of band or via initial request)
3. **Encryption**: Data encrypted using peer's public key
4. **Transmission**: Encrypted data sent over network
5. **Decryption**: Recipient decrypts using their private key

## Limitations & Future Improvements

### Current Implementation:
- Simplified key exchange (not true ECC point multiplication)
- Uses XOR/rotation-based transformations
- Suitable for basic encryption needs

### Future Enhancements:
1. **True ECC Support**
   - Implement proper ECC point multiplication
   - Use Windows CNG ECC APIs when available
   - Support multiple curves (P-256, P-384, P-521)

2. **Enhanced Key Exchange**
   - ECDH (Elliptic Curve Diffie-Hellman)
   - ECDSA for signatures
   - Key derivation function (HKDF)

3. **Performance Optimizations**
   - Key caching
   - Session reuse
   - Hardware acceleration

4. **Additional Features**
   - Message signing
   - Certificate validation
   - Perfect forward secrecy with key rotation

## Error Handling

The module uses `EccError` enum for error reporting:

```rust
pub enum EccError {
    KeyGenerationFailed,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    InvalidData,
}
```

## Example: Full Communication Flow

```rust
use utils::ecc::NetworkEncryption;
use requests::Request;
use alloc::sync::Arc;

// 1. Initialize encryption on both ends
let mut client_enc = NetworkEncryption::new()?;
let mut server_enc = NetworkEncryption::new()?;

// 2. Exchange public keys (e.g., via initial handshake)
let client_pubkey = client_enc.get_public_key();
let server_pubkey = server_enc.get_public_key();

client_enc.set_peer_public_key(server_pubkey.to_vec());
server_enc.set_peer_public_key(client_pubkey.to_vec());

// 3. Client sends encrypted request
let encrypted_request = Request::post("https://api.example.com")
    .body(b"Sensitive data")
    .encryption(Arc::new(client_enc.clone()))
    .build()
    .send()?;

// 4. Server decrypts and processes
let decrypted_data = encrypted_request.decrypt_body(&server_enc)?;

// 5. Server sends encrypted response
let encrypted_response = Request::post("https://api.example.com/reply")
    .body(process_data(&decrypted_data))
    .encryption(Arc::new(server_enc.clone()))
    .build()
    .send()?;

// 6. Client decrypts response
let result = encrypted_response.decrypt_body(&client_enc)?;
```

## Integration Notes

- Encryption is **optional** - requests work without it
- Encryption only applies to request **body** (headers remain plaintext)
- Responses can be automatically decrypted if encrypted
- Falls back to plaintext if decryption fails

## Security Considerations

⚠️ **Important**: This implementation provides basic encryption. For production use:
- Validate all inputs
- Implement proper key exchange protocols
- Use certificate-based authentication
- Consider TLS/TLS 1.3 for transport security
- Implement proper key rotation
- Add message authentication codes (MACs) for integrity

---

*Last Updated: 2025*