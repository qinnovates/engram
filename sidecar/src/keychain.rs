//! macOS Keychain integration via Security.framework.
//!
//! Uses the security-framework crate which wraps Apple's native
//! Security.framework APIs. Keys are stored and retrieved via the
//! OS keychain — on Apple Silicon, this uses the Secure Enclave.
//!
//! The key goes: Keychain → this process's mlock'd memory → age stdin
//! It NEVER: touches disk, enters Python, appears in process args

use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use std::str;

const SERVICE: &str = "engram";

/// Get the public key for a tier from Keychain.
/// Public keys are safe to return — not secret.
pub fn get_public_key(tier: &str) -> Result<String, String> {
    let account = format!("{}-pubkey", tier);
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => str::from_utf8(&bytes)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Invalid UTF-8 in public key: {}", e)),
        Err(e) => Err(format!("Public key not found for tier '{}': {}", tier, e)),
    }
}

/// Get the private key for a tier from Keychain.
/// This is the security-critical operation — the key enters this process's
/// mlock'd memory, is piped to age, then zeroed via zeroize.
pub fn get_private_key(tier: &str) -> Result<String, String> {
    let account = format!("{}-key", tier);
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => str::from_utf8(&bytes)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Invalid UTF-8 in private key: {}", e)),
        Err(e) => Err(format!("Private key not found for tier '{}'. Run 'engram-vault KEYGEN {}' first. Error: {}", tier, tier, e)),
    }
}

/// Store a public key for a tier in Keychain.
pub fn store_public_key(tier: &str, pubkey: &str) -> Result<(), String> {
    let account = format!("{}-pubkey", tier);

    // Delete existing entry if present
    let _ = delete_generic_password(SERVICE, &account);

    set_generic_password(SERVICE, &account, pubkey.as_bytes())
        .map_err(|e| format!("Keychain store failed for {}: {}", account, e))
}

/// Store a private key for a tier in Keychain.
/// On Apple Silicon, the Keychain item can be protected by the Secure Enclave.
pub fn store_private_key(tier: &str, privkey: &str) -> Result<(), String> {
    let account = format!("{}-key", tier);

    // Delete existing entry if present
    let _ = delete_generic_password(SERVICE, &account);

    set_generic_password(SERVICE, &account, privkey.as_bytes())
        .map_err(|e| format!("Keychain store failed for {}: {}", account, e))
}
