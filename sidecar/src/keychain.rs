//! macOS Keychain integration via Security.framework.
//!
//! Uses the security-framework crate which wraps Apple's native
//! Security.framework APIs. Keys are stored in the macOS login keychain
//! (software keychain), NOT the Secure Enclave. The Secure Enclave only
//! supports P-256 asymmetric operations, not ML-KEM/X25519 keys.
//! Keys are protected by the user's login password and (if configured)
//! biometric unlock, but they are extractable via Keychain API.
//!
//! Key flow: Keychain -> this process's mlock'd memory -> crypto ops -> zeroed
//! It NEVER: touches disk, enters Python, appears in process args

use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use std::str;

const SERVICE: &str = "engram";

/// Allowed tier values (defense-in-depth, also validated in main.rs)
const VALID_TIERS: &[&str] = &["warm", "cold", "frozen", "hot", "test", "index"];

fn validate_tier(tier: &str) -> Result<(), String> {
    if VALID_TIERS.contains(&tier) {
        Ok(())
    } else {
        Err(format!("Invalid tier '{}'", tier))
    }
}

/// Get the public key for a tier from Keychain.
/// Public keys are safe to return — not secret.
pub(crate) fn get_public_key(tier: &str) -> Result<String, String> {
    validate_tier(tier)?;
    let account = format!("{}-pubkey", tier);
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => str::from_utf8(&bytes)
            .map(|s| s.trim().to_string())
            .map_err(|_| "Invalid UTF-8 in public key".to_string()),
        Err(_) => Err(format!("Public key not found for tier '{}'", tier)),
    }
}

/// Get the private key for a tier from Keychain.
/// The key enters this process's mlock'd memory, is used for
/// in-process crypto ops (ML-KEM + AES-256-GCM), then zeroed.
pub(crate) fn get_private_key(tier: &str) -> Result<String, String> {
    validate_tier(tier)?;
    let account = format!("{}-key", tier);
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => str::from_utf8(&bytes)
            .map(|s| s.trim().to_string())
            .map_err(|_| "Invalid UTF-8 in private key".to_string()),
        Err(_) => Err(format!("Private key not found for tier '{}'. Run KEYGEN first", tier)),
    }
}

/// Store a public key for a tier in Keychain.
pub(crate) fn store_public_key(tier: &str, pubkey: &str) -> Result<(), String> {
    validate_tier(tier)?;
    let account = format!("{}-pubkey", tier);

    // Try to set first; if item exists, delete then retry
    match set_generic_password(SERVICE, &account, pubkey.as_bytes()) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = delete_generic_password(SERVICE, &account);
            set_generic_password(SERVICE, &account, pubkey.as_bytes())
                .map_err(|_| format!("Keychain store failed for {}", account))
        }
    }
}

/// Store a private key for a tier in Keychain.
/// Uses set-first-then-delete-and-retry pattern to avoid destroying
/// existing keys if the write fails.
pub(crate) fn store_private_key(tier: &str, privkey: &str) -> Result<(), String> {
    validate_tier(tier)?;
    let account = format!("{}-key", tier);

    // Try to set first; if item already exists, delete then retry.
    // This avoids the delete-before-write pattern where a failed write
    // after a successful delete would permanently destroy the key.
    match set_generic_password(SERVICE, &account, privkey.as_bytes()) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = delete_generic_password(SERVICE, &account);
            set_generic_password(SERVICE, &account, privkey.as_bytes())
                .map_err(|_| format!("Keychain store failed for {}", account))
        }
    }
}
