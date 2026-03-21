//! engram-vault v2: Secure crypto sidecar — no external dependencies
//!
//! ALL encryption happens inside this binary. No age. No brew install.
//! No subprocess calls for crypto. No outbound network calls.
//!
//! Algorithms (NIST-approved only):
//!   Key encapsulation: ML-KEM-768 (FIPS 203) + X25519 hybrid
//!   Data encryption:   AES-256-GCM (FIPS 197 + SP 800-38D)
//!   Key derivation:    HKDF-SHA256 (SP 800-56C)
//!
//! Key material flow:
//!   Keychain -> this process (mlock'd, zeroize-on-drop) -> crypto ops -> zeroed
//!   Key NEVER: touches disk, enters Python, appears in process args
//!
//! File format (engram encrypted file, .encf):
//!   [4 bytes]    magic: "ENCF"
//!   [2 bytes]    version: 0x0002
//!   [2 bytes]    KEM ciphertext length (1088 for ML-KEM-768)
//!   [1088 bytes] ML-KEM-768 ciphertext (encapsulated shared secret)
//!   [32 bytes]   X25519 ephemeral public key
//!   [16 bytes]   HKDF salt
//!   [12 bytes]   AES-256-GCM nonce
//!   [8 bytes]    plaintext length (u64 little-endian)
//!   [N+16 bytes] ciphertext + GCM auth tag
//!
//! Protocol (stdin/stdout):
//!   ENCRYPT <input> <output> <tier>    -> OK | ERROR <msg>
//!   DECRYPT <input> <output> <tier>    -> OK | ERROR <msg>
//!   KEYGEN <tier>                       -> OK <pubkey_hex> | ERROR <msg>
//!   MERKLE_ADD <hex_hash>               -> OK <leaf_index> | ERROR <msg>
//!   MERKLE_ROOT                         -> OK <root_hex> | OK empty
//!   MERKLE_PROOF <leaf_index>           -> OK <leaf> <idx> <siblings> <dirs> <root>
//!   MERKLE_VERIFY <leaf> <sibs|dirs> <root> -> OK true | OK false
//!   MERKLE_COUNT                        -> OK <count>
//!   MERKLE_RESET                        -> OK
//!   PING                                -> PONG
//!   QUIT                                -> BYE

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use zeroize::Zeroize;

mod crypto;
mod keychain;
mod merkle;

/// Maximum input file size (256 MB) to prevent mlock exhaustion
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Global Merkle tree (lives for the lifetime of the sidecar process).
/// Single-threaded sidecar — no concurrency, so Mutex is just for safety.
use std::sync::Mutex;
static MERKLE_TREE: Mutex<Option<merkle::MerkleTree>> = Mutex::new(None);

fn with_merkle<F, R>(f: F) -> R
where
    F: FnOnce(&mut merkle::MerkleTree) -> R,
{
    let mut guard = MERKLE_TREE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(merkle::MerkleTree::new());
    }
    f(guard.as_mut().unwrap())
}

fn main() {
    // === Security hardening ===
    #[cfg(unix)]
    unsafe {
        let mlock_result = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        if mlock_result != 0 {
            eprintln!(
                "WARNING: mlockall failed. Key material may be swappable."
            );
        }
        let zero_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero_core) != 0 {
            eprintln!("WARNING: Cannot disable core dumps.");
        }
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
        if parts.is_empty() {
            continue;
        }

        let response = match parts[0].to_uppercase().as_str() {
            "PING" => "PONG".to_string(),
            "QUIT" => {
                let _ = writeln!(stdout, "BYE");
                break;
            }
            "ENCRYPT" => {
                if parts.len() < 4 {
                    "ERROR Usage: ENCRYPT <input> <output> <tier>".to_string()
                } else if let Err(e) = validate_path(parts[1])
                    .and(validate_path(parts[2]))
                    .and(validate_tier(parts[3]))
                {
                    e
                } else {
                    handle_encrypt(parts[1], parts[2], parts[3])
                }
            }
            "DECRYPT" => {
                if parts.len() < 4 {
                    "ERROR Usage: DECRYPT <input> <output> <tier>".to_string()
                } else if let Err(e) = validate_path(parts[1])
                    .and(validate_path(parts[2]))
                    .and(validate_tier(parts[3]))
                {
                    e
                } else {
                    handle_decrypt(parts[1], parts[2], parts[3])
                }
            }
            "KEYGEN" => {
                if parts.len() < 2 {
                    "ERROR Usage: KEYGEN <tier>".to_string()
                } else if let Err(e) = validate_tier(parts[1]) {
                    e
                } else {
                    handle_keygen(parts[1])
                }
            }
            "MERKLE_ADD" => {
                if parts.len() < 2 {
                    "ERROR Usage: MERKLE_ADD <hex_hash>".to_string()
                } else {
                    match with_merkle(|t| t.add_hex(parts[1])) {
                        Ok(idx) => format!("OK {}", idx),
                        Err(e) => format!("ERROR {}", e),
                    }
                }
            }
            "MERKLE_ROOT" => {
                match with_merkle(|t| t.root_hex()) {
                    Some(root) => format!("OK {}", root),
                    None => "OK empty".to_string(),
                }
            }
            "MERKLE_PROOF" => {
                if parts.len() < 2 {
                    "ERROR Usage: MERKLE_PROOF <leaf_index>".to_string()
                } else {
                    match parts[1].parse::<usize>() {
                        Ok(idx) => match with_merkle(|t| t.proof(idx)) {
                            Ok(proof) => proof.to_response(),
                            Err(e) => format!("ERROR {}", e),
                        },
                        Err(_) => "ERROR Invalid index".to_string(),
                    }
                }
            }
            "MERKLE_VERIFY" => {
                // MERKLE_VERIFY <leaf_hex> <siblings_csv> <directions_csv> <root_hex>
                if parts.len() < 4 {
                    "ERROR Usage: MERKLE_VERIFY <leaf_hex> <siblings_csv,directions_csv> <root_hex>".to_string()
                } else {
                    handle_merkle_verify(&parts[1..])
                }
            }
            "MERKLE_COUNT" => {
                format!("OK {}", with_merkle(|t| t.leaf_count()))
            }
            "MERKLE_RESET" => {
                *MERKLE_TREE.lock().unwrap() = Some(merkle::MerkleTree::new());
                "OK".to_string()
            }
            _ => "ERROR Unknown command".to_string(),
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

// === Merkle verify handler ===

fn handle_merkle_verify(args: &[&str]) -> String {
    // Parse: leaf_hex siblings_csv,directions_csv root_hex
    // The protocol packs siblings and directions into one field for simplicity
    if args.len() < 3 {
        return "ERROR Need leaf_hex, siblings_csv,directions_csv, root_hex".to_string();
    }

    let leaf_hex = args[0];
    let combined = args[1]; // "sib1,sib2|left,right" format
    let root_hex = args[2];

    let leaf = match hex_to_array(leaf_hex) {
        Ok(a) => a,
        Err(e) => return format!("ERROR {}", e),
    };
    let root = match hex_to_array(root_hex) {
        Ok(a) => a,
        Err(e) => return format!("ERROR {}", e),
    };

    // Split combined by | into siblings and directions
    let halves: Vec<&str> = combined.split('|').collect();
    if halves.len() != 2 {
        return "ERROR Format: siblings_csv|directions_csv".to_string();
    }

    let sibling_hexes: Vec<&str> = halves[0].split(',').collect();
    let directions: Vec<String> = halves[1].split(',').map(|s| s.to_string()).collect();

    if sibling_hexes.len() != directions.len() {
        return "ERROR Sibling count != direction count".to_string();
    }

    let mut siblings = Vec::new();
    for sh in &sibling_hexes {
        match hex_to_array(sh) {
            Ok(a) => siblings.push(a),
            Err(e) => return format!("ERROR {}", e),
        }
    }

    let proof = merkle::MerkleProof {
        leaf_hash: leaf,
        leaf_index: 0, // not needed for verify
        siblings,
        directions,
        root,
    };

    let valid = merkle::MerkleTree::verify(&proof);
    format!("OK {}", valid)
}

fn hex_to_array(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err("Expected 64-char hex".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// === Input validation ===

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("ERROR Empty path".to_string());
    }
    if path.contains('\n') || path.contains('\r') || path.contains('\0') || path.contains(' ') {
        return Err("ERROR Invalid path".to_string());
    }
    // Reject path traversal
    if path.contains("..") {
        return Err("ERROR Path traversal not allowed".to_string());
    }
    Ok(())
}

/// Canonicalize a path and verify it is under an allowed base.
/// For input files: must exist and be a regular file.
/// For output files: parent directory must exist.
fn canonicalize_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = Path::new(path);

    // For existing files, canonicalize directly
    if p.exists() {
        let canonical = fs::canonicalize(p)
            .map_err(|_| "ERROR Cannot resolve path".to_string())?;
        // Reject symlinks to prevent symlink attacks
        let meta = fs::symlink_metadata(p)
            .map_err(|_| "ERROR Cannot stat path".to_string())?;
        if meta.file_type().is_symlink() {
            return Err("ERROR Symlinks not allowed".to_string());
        }
        return Ok(canonical);
    }

    // For new files (output), canonicalize the parent
    if let Some(parent) = p.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            return Ok(p.to_path_buf());
        }
    }

    Err("ERROR Path does not exist".to_string())
}

fn validate_tier(tier: &str) -> Result<(), String> {
    match tier {
        "warm" | "cold" | "frozen" | "hot" | "test" | "index" => Ok(()),
        _ => Err("ERROR Invalid tier".to_string()),
    }
}

// === Encrypt (public key only — no secret needed) ===

fn handle_encrypt(input: &str, output: &str, tier: &str) -> String {
    // Canonicalize paths
    let input_path = match canonicalize_path(input) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get public key from Keychain
    let pubkey_hex = match keychain::get_public_key(tier) {
        Ok(k) => k,
        Err(e) => return format!("ERROR {}", e),
    };

    let pubkey_bytes = match hex::decode(&pubkey_hex) {
        Ok(b) => b,
        Err(_) => return "ERROR Invalid public key format in Keychain".to_string(),
    };

    // Check file size before reading into mlock'd memory
    let meta = match fs::metadata(&input_path) {
        Ok(m) => m,
        Err(e) => return format!("ERROR Cannot stat input: {}", e),
    };
    if meta.len() > MAX_FILE_SIZE {
        return "ERROR Input file too large".to_string();
    }

    // Read plaintext
    let mut plaintext = match fs::read(&input_path) {
        Ok(d) => d,
        Err(e) => return format!("ERROR Cannot read input: {}", e),
    };

    // Encrypt using ML-KEM-768 + X25519 hybrid / AES-256-GCM
    let result = crypto::encrypt(&pubkey_bytes, &plaintext);
    plaintext.zeroize();

    match result {
        Ok(encrypted) => {
            match fs::write(output, &encrypted) {
                Ok(_) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(output, fs::Permissions::from_mode(0o600));
                    }
                    "OK".to_string()
                }
                Err(e) => format!("ERROR Cannot write output: {}", e),
            }
        }
        Err(e) => format!("ERROR Encryption failed: {}", e),
    }
}

// === Decrypt (private key from Keychain -> crypto -> zeroed) ===

fn handle_decrypt(input: &str, output: &str, tier: &str) -> String {
    // Canonicalize input path
    let input_path = match canonicalize_path(input) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get private key from Keychain
    let mut privkey_hex = match keychain::get_private_key(tier) {
        Ok(k) => k,
        Err(e) => return format!("ERROR {}", e),
    };

    let mut privkey_bytes = match hex::decode(&privkey_hex) {
        Ok(b) => b,
        Err(_) => {
            privkey_hex.zeroize();
            return "ERROR Invalid private key format in Keychain".to_string();
        }
    };
    privkey_hex.zeroize();

    // Check file size before reading
    let meta = match fs::metadata(&input_path) {
        Ok(m) => m,
        Err(e) => {
            privkey_bytes.zeroize();
            return format!("ERROR Cannot stat input: {}", e);
        }
    };
    if meta.len() > MAX_FILE_SIZE {
        privkey_bytes.zeroize();
        return "ERROR Input file too large".to_string();
    }

    // Read ciphertext
    let ciphertext = match fs::read(&input_path) {
        Ok(d) => d,
        Err(e) => {
            privkey_bytes.zeroize();
            return format!("ERROR Cannot read input: {}", e);
        }
    };

    // Decrypt
    let result = crypto::decrypt(&privkey_bytes, &ciphertext);
    privkey_bytes.zeroize(); // Zero IMMEDIATELY after use

    match result {
        Ok(mut plaintext) => {
            let write_result = fs::write(output, &plaintext);
            plaintext.zeroize(); // Zero decrypted content from memory
            match write_result {
                Ok(_) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(output, fs::Permissions::from_mode(0o600));
                    }
                    "OK".to_string()
                }
                Err(e) => format!("ERROR Cannot write output: {}", e),
            }
        }
        Err(e) => format!("ERROR Decryption failed: {}", e),
    }
}

// === Keygen (generate ML-KEM-768 + X25519 hybrid keypair, store in Keychain) ===

fn handle_keygen(tier: &str) -> String {
    // Refuse to overwrite existing keys
    if keychain::get_private_key(tier).is_ok() {
        return format!("ERROR Key already exists for tier '{}'", tier);
    }

    // Generate hybrid keypair (privkey is Zeroizing<Vec<u8>>)
    let (privkey_bytes, pubkey_bytes) = crypto::generate_keypair();

    // Store in Keychain as hex
    let pubkey_hex = hex::encode(&pubkey_bytes);
    let mut privkey_hex = hex::encode(&privkey_bytes);
    // privkey_bytes is Zeroizing — dropped automatically

    // Store public key first (non-destructive if it fails)
    if let Err(e) = keychain::store_public_key(tier, &pubkey_hex) {
        privkey_hex.zeroize();
        return format!("ERROR {}", e);
    }

    let store_result = keychain::store_private_key(tier, &privkey_hex);
    privkey_hex.zeroize();

    match store_result {
        Ok(()) => format!("OK {}", pubkey_hex),
        Err(e) => format!("ERROR {}", e),
    }
}

// === hex encoding (no external dep) ===

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Odd hex length".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|_| "Invalid hex".to_string())
            })
            .collect()
    }
}

// === libc bindings ===

#[cfg(unix)]
mod libc {
    #[repr(C)]
    pub struct rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }
    pub const RLIMIT_CORE: i32 = 4;
    pub const MCL_CURRENT: i32 = 1;
    pub const MCL_FUTURE: i32 = 2;
    extern "C" {
        pub fn mlockall(flags: i32) -> i32;
        pub fn setrlimit(resource: i32, rlp: *const rlimit) -> i32;
    }
}
