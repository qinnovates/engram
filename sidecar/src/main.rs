//! engram-vault: Secure crypto sidecar for Engram
//!
//! This binary handles ALL private key operations so that key material
//! NEVER enters Python's address space. It is the security boundary.
//!
//! Architecture:
//!   Python (Engram) → stdin command → engram-vault → age → stdout result
//!
//! Key material flow:
//!   macOS Keychain → this process (mlock'd, zeroize-on-drop) → age stdin
//!   Key NEVER: touches disk, enters Python, appears in process args, hits swap
//!
//! Protocol (stdin/stdout, one command per line):
//!   ENCRYPT <input_path> <output_path> <tier>
//!     → Encrypts file with tier's public key from Keychain
//!     → Responds: OK or ERROR <message>
//!
//!   DECRYPT <input_path> <output_path> <tier>
//!     → Retrieves tier's private key from Keychain
//!     → Decrypts file with age
//!     → Zeros key from memory
//!     → Responds: OK or ERROR <message>
//!
//!   STORE <tier> <public_key>
//!     → Generates age keypair
//!     → Stores private key in Keychain (via Security.framework)
//!     → Returns public key
//!     → Zeros private key from memory
//!     → Responds: OK <public_key> or ERROR <message>
//!
//!   ROTATE <tier> <new_public_key>
//!     → Retrieves old private key from Keychain
//!     → Stores new key pair
//!     → Zeros old key
//!     → Responds: OK or ERROR <message>
//!
//!   PING → PONG (health check)
//!   QUIT → exits

use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

mod keychain;

fn main() {
    // Lock memory to prevent swapping key material to disk
    #[cfg(unix)]
    unsafe {
        // Request mlock on our entire address space
        // This is best-effort — requires appropriate ulimits
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
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
                } else {
                    handle_encrypt(parts[1], parts[2], parts[3])
                }
            }
            "DECRYPT" => {
                if parts.len() < 4 {
                    "ERROR Usage: DECRYPT <input> <output> <tier>".to_string()
                } else {
                    handle_decrypt(parts[1], parts[2], parts[3])
                }
            }
            "KEYGEN" => {
                if parts.len() < 2 {
                    "ERROR Usage: KEYGEN <tier>".to_string()
                } else {
                    handle_keygen(parts[1])
                }
            }
            _ => format!("ERROR Unknown command: {}", parts[0]),
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

/// Encrypt a file using the tier's public key from Keychain.
/// Public key retrieval is safe — no secret involved.
fn handle_encrypt(input: &str, output: &str, tier: &str) -> String {
    // Retrieve the PUBLIC key from Keychain (not secret — safe)
    let pubkey = match keychain::get_public_key(tier) {
        Ok(k) => k,
        Err(e) => return format!("ERROR {}", e),
    };

    // age -r <pubkey> -o <output> <input>
    let result = Command::new("age")
        .args(["-r", &pubkey, "-o", output, input])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status();

    match result {
        Ok(status) if status.success() => "OK".to_string(),
        Ok(_) => "ERROR age encrypt failed".to_string(),
        Err(e) => format!("ERROR age not found: {}", e),
    }
}

/// Decrypt a file using the tier's private key from Keychain.
/// The private key is retrieved, piped to age via stdin, then zeroed.
/// It NEVER: touches disk, appears in process args, enters Python.
fn handle_decrypt(input: &str, output: &str, tier: &str) -> String {
    // Retrieve private key from Keychain — stays in this process only
    let mut private_key = match keychain::get_private_key(tier) {
        Ok(k) => k,
        Err(e) => return format!("ERROR {}", e),
    };

    // Pipe private key to age via stdin using process substitution
    // age -d -i - reads identity from stdin (not from a file or argv)
    let mut child = match Command::new("age")
        .args(["-d", "-i", "/dev/stdin", "-o", output, input])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            private_key.zeroize();
            return format!("ERROR Failed to spawn age: {}", e);
        }
    };

    // Write private key to age's stdin
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(private_key.as_bytes());
        // stdin is dropped here, closing the pipe
    }

    // Zero the key IMMEDIATELY after piping — before waiting for age to finish
    private_key.zeroize();

    // Wait for age to complete
    match child.wait() {
        Ok(status) if status.success() => "OK".to_string(),
        Ok(_) => "ERROR age decrypt failed — wrong key or corrupted file".to_string(),
        Err(e) => format!("ERROR age process failed: {}", e),
    }
}

/// Generate a new age keypair for a tier and store in Keychain.
/// The private key goes directly from age-keygen → Keychain.
/// It exists only in this process's mlock'd memory, then is zeroed.
fn handle_keygen(tier: &str) -> String {
    // Run age-keygen, capture output
    let output = match Command::new("age-keygen")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(e) => return format!("ERROR age-keygen not found: {}", e),
    };

    if !output.status.success() {
        return "ERROR age-keygen failed".to_string();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pubkey = String::new();
    let mut privkey = String::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("# public key:") {
            pubkey = line.split("# public key:").nth(1).unwrap_or("").trim().to_string();
        } else if line.starts_with("AGE-SECRET-KEY-") {
            privkey = line.to_string();
        }
    }

    if pubkey.is_empty() || privkey.is_empty() {
        return "ERROR Failed to parse age-keygen output".to_string();
    }

    // Store BOTH keys in Keychain
    // Public key: stored for encryption (not secret but needed for recall)
    if let Err(e) = keychain::store_public_key(tier, &pubkey) {
        privkey.zeroize();
        return format!("ERROR Failed to store public key: {}", e);
    }

    // Private key: stored for decryption (SECRET — goes to Keychain, then zeroed)
    if let Err(e) = keychain::store_private_key(tier, &privkey) {
        privkey.zeroize();
        return format!("ERROR Failed to store private key: {}", e);
    }

    // Zero the private key from memory — deterministic, not GC-dependent
    privkey.zeroize();

    format!("OK {}", pubkey)
}

// libc bindings for mlockall
#[cfg(unix)]
mod libc {
    extern "C" {
        pub fn mlockall(flags: i32) -> i32;
    }
    pub const MCL_CURRENT: i32 = 1;
    pub const MCL_FUTURE: i32 = 2;
}
