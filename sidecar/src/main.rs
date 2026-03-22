//! engram-vault v2: Secure crypto sidecar + Merkle-Index
//!
//! ALL encryption AND integrity verification happens inside this binary.
//! Python is a thin CLI wrapper. No JSON parsing for search — sidecar holds the index.
//!
//! Algorithms (NIST-approved only):
//!   Key encapsulation: ML-KEM-768 (FIPS 203) + X25519 hybrid
//!   Data encryption:   AES-256-GCM (FIPS 197 + SP 800-38D)
//!   Key derivation:    HKDF-SHA3-256 (SP 800-56C + FIPS 202)
//!   Merkle hashing:    SHA3-256 (FIPS 202)
//!   Root sealing:      HMAC-SHA3-256 (FIPS 198-1 + FIPS 202)
//!
//! Protocol (stdin/stdout):
//!   ENCRYPT <input> <output> <tier>         -> OK | ERROR
//!   DECRYPT <input> <output> <tier>         -> OK | ERROR
//!   KEYGEN <tier>                            -> OK <pubkey_hex>
//!   MERKLE_ADD <hex_hash>                    -> OK <leaf_index>
//!   MERKLE_ROOT                              -> OK <root_hex> | OK empty
//!   MERKLE_PROOF <leaf_index>                -> OK <proof_fields>
//!   MERKLE_VERIFY <leaf> <sibs|dirs> <root>  -> OK true | OK false
//!   MERKLE_COUNT                             -> OK <count>
//!   MERKLE_SEAL                              -> OK <seal_hex> (key derived internally)
//!   MERKLE_VERIFY_SEAL <seal_hex>            -> OK true | OK false
//!   MERKLE_RESET                             -> OK
//!   INDEX_ADD <json_payload>                 -> OK <leaf_index>
//!   INDEX_SEARCH <query>                     -> OK <json_results>
//!   INDEX_LOOKUP <hex_hash>                  -> OK <json_result> | OK null
//!   INDEX_STATS                              -> OK <json_stats>
//!   INDEX_SEAL_KEY <hex_key_material>        -> OK (derives seal key via HKDF)
//!   PING                                     -> PONG
//!   QUIT                                     -> BYE

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use zeroize::Zeroize;

mod crypto;
mod keychain;
mod merkle;

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

use std::sync::Mutex;
static MERKLE_INDEX: Mutex<Option<merkle::MerkleIndex>> = Mutex::new(None);

fn with_index<F, R>(f: F) -> R
where
    F: FnOnce(&mut merkle::MerkleIndex) -> R,
{
    let mut guard = MERKLE_INDEX.lock().unwrap_or_else(|e| e.into_inner()); // Fix #10: recover from poison
    if guard.is_none() {
        *guard = Some(merkle::MerkleIndex::new());
    }
    f(guard.as_mut().unwrap())
}

fn main() {
    #[cfg(unix)]
    unsafe {
        let mlock_result = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        if mlock_result != 0 {
            eprintln!("WARNING: mlockall failed. Key material may be swappable.");
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

        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        // Split into command + rest (not limited to 4 parts — Fix #11)
        let (cmd, rest) = match trimmed.find(' ') {
            Some(pos) => (trimmed[..pos].to_uppercase(), trimmed[pos+1..].trim()),
            None => (trimmed.to_uppercase(), ""),
        };

        let response = match cmd.as_str() {
            "PING" => "PONG".to_string(),
            "QUIT" => {
                let _ = writeln!(stdout, "BYE");
                break;
            }

            // ── Crypto commands (unchanged) ──

            "ENCRYPT" => {
                let parts: Vec<&str> = rest.splitn(3, ' ').collect();
                if parts.len() < 3 {
                    "ERROR Usage: ENCRYPT <input> <output> <tier>".to_string()
                } else if let Err(e) = validate_path(parts[0])
                    .and(validate_path(parts[1]))
                    .and(validate_tier(parts[2]))
                {
                    e
                } else {
                    handle_encrypt(parts[0], parts[1], parts[2])
                }
            }
            "DECRYPT" => {
                let parts: Vec<&str> = rest.splitn(3, ' ').collect();
                if parts.len() < 3 {
                    "ERROR Usage: DECRYPT <input> <output> <tier>".to_string()
                } else if let Err(e) = validate_path(parts[0])
                    .and(validate_path(parts[1]))
                    .and(validate_tier(parts[2]))
                {
                    e
                } else {
                    handle_decrypt(parts[0], parts[1], parts[2])
                }
            }
            "KEYGEN" => {
                if rest.is_empty() {
                    "ERROR Usage: KEYGEN <tier>".to_string()
                } else if let Err(e) = validate_tier(rest) {
                    e
                } else {
                    handle_keygen(rest)
                }
            }

            // ── Merkle commands ──

            "MERKLE_ADD" => {
                if rest.is_empty() {
                    "ERROR Usage: MERKLE_ADD <hex_hash>".to_string()
                } else {
                    match with_index(|idx| idx.add_hex(rest)) {
                        Ok(i) => format!("OK {}", i),
                        Err(e) => format!("ERROR {}", e),
                    }
                }
            }
            "MERKLE_ROOT" => {
                match with_index(|idx| idx.root_hex()) {
                    Some(root) => format!("OK {}", root),
                    None => "OK empty".to_string(),
                }
            }
            "MERKLE_PROOF" => {
                match rest.parse::<usize>() {
                    Ok(i) => match with_index(|idx| idx.proof(i)) {
                        Ok(proof) => proof.to_response(),
                        Err(e) => format!("ERROR {}", e),
                    },
                    Err(_) => "ERROR Invalid index".to_string(),
                }
            }
            "MERKLE_VERIFY" => {
                handle_merkle_verify(rest)
            }
            "MERKLE_COUNT" => {
                format!("OK {}", with_index(|idx| idx.leaf_count()))
            }
            "MERKLE_SEAL" => {
                // Fix #2: seal key derived internally — no key argument needed
                match with_index(|idx| idx.seal_root()) {
                    Ok(seal) => format!("OK {}", seal),
                    Err(e) => format!("ERROR {}", e),
                }
            }
            "MERKLE_VERIFY_SEAL" => {
                if rest.is_empty() {
                    "ERROR Usage: MERKLE_VERIFY_SEAL <seal_hex>".to_string()
                } else {
                    match with_index(|idx| idx.verify_seal(rest)) {
                        Ok(valid) => format!("OK {}", valid),
                        Err(e) => format!("ERROR {}", e),
                    }
                }
            }
            "MERKLE_RESET" => {
                with_index(|idx| idx.reset());
                "OK".to_string()
            }

            // ── Index commands (NEW — the fast path) ──

            "INDEX_SEAL_KEY" => {
                // Set seal key material (from Keychain, via Python startup)
                if rest.is_empty() {
                    "ERROR Usage: INDEX_SEAL_KEY <hex_key_material>".to_string()
                } else {
                    match merkle::hex_decode(rest) {
                        Ok(bytes) => {
                            with_index(|idx| idx.set_seal_key_material(&bytes));
                            "OK".to_string()
                        }
                        Err(e) => format!("ERROR {}", e),
                    }
                }
            }
            "INDEX_ADD" => {
                // Add artifact with full payload (JSON on the rest of the line)
                handle_index_add(rest)
            }
            "INDEX_SEARCH" => {
                if rest.is_empty() {
                    "ERROR Usage: INDEX_SEARCH <query>".to_string()
                } else {
                    handle_index_search(rest)
                }
            }
            "INDEX_LOOKUP" => {
                if rest.is_empty() {
                    "ERROR Usage: INDEX_LOOKUP <hex_hash>".to_string()
                } else {
                    handle_index_lookup(rest)
                }
            }
            "INDEX_STATS" => {
                handle_index_stats()
            }

            _ => "ERROR Unknown command".to_string(),
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

// ── Index command handlers ──

fn handle_index_add(json_str: &str) -> String {
    // Parse JSON payload into LeafPayload
    // Format: {"hash":"<64hex>","summary":"...","keywords":["..."],"tier":"...","path":"...","created_at":0.0,"last_accessed":0.0,"sections":["..."]}
    let parsed: Result<serde_json_minimal::Value, _> = parse_json_value(json_str);
    match parsed {
        Ok(val) => {
            let hash_hex = val.get_str("hash").unwrap_or("");
            let hash_bytes = match merkle::hex_decode(hash_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return "ERROR Invalid hash".to_string(),
            };

            let payload = merkle::LeafPayload {
                content_hash: hash_bytes,
                summary: val.get_str("summary").unwrap_or("").to_string(),
                keywords: val.get_str_array("keywords"),
                tier: val.get_str("tier").unwrap_or("hot").to_string(),
                path: val.get_str("path").unwrap_or("").to_string(),
                created_at: val.get_f64("created_at").unwrap_or(0.0),
                last_accessed: val.get_f64("last_accessed").unwrap_or(0.0),
                section_headers: val.get_str_array("sections"),
            };

            match with_index(|idx| idx.add_artifact(payload)) {
                Ok(i) => format!("OK {}", i),
                Err(e) => format!("ERROR {}", e),
            }
        }
        Err(e) => format!("ERROR JSON parse failed: {}", e),
    }
}

fn handle_index_search(query: &str) -> String {
    let results = with_index(|idx| idx.search(query));

    // Format as JSON array
    let json_results: Vec<String> = results.iter().map(|r| {
        format!(
            r#"{{"hash":"{}","summary":"{}","tier":"{}","path":"{}","keywords":[{}],"leaf_index":{},"root":"{}"}}"#,
            merkle::hex_encode(&r.payload.content_hash),
            escape_json(&r.payload.summary),
            r.payload.tier,
            escape_json(&r.payload.path),
            r.payload.keywords.iter().map(|k| format!(r#""{}""#, escape_json(k))).collect::<Vec<_>>().join(","),
            r.leaf_index,
            merkle::hex_encode(&r.proof.root),
        )
    }).collect();

    format!("OK [{}]", json_results.join(","))
}

fn handle_index_lookup(hex: &str) -> String {
    match with_index(|idx| idx.lookup_hex(hex)) {
        Ok(Some(r)) => {
            format!(
                r#"OK {{"hash":"{}","summary":"{}","tier":"{}","path":"{}","leaf_index":{},"root":"{}"}}"#,
                merkle::hex_encode(&r.payload.content_hash),
                escape_json(&r.payload.summary),
                r.payload.tier,
                escape_json(&r.payload.path),
                r.leaf_index,
                merkle::hex_encode(&r.proof.root),
            )
        }
        Ok(None) => "OK null".to_string(),
        Err(e) => format!("ERROR {}", e),
    }
}

fn handle_index_stats() -> String {
    let stats = with_index(|idx| idx.stats());
    format!(
        r#"OK {{"version":{},"artifacts":{},"leaves":{},"keywords":{},"keyword_refs":{},"sealed":{},"manifest":{}}}"#,
        stats.version, stats.artifact_count, stats.leaf_count,
        stats.keyword_entries, stats.keyword_refs, stats.has_seal, stats.has_manifest,
    )
}

// ── Merkle verify handler ──

fn handle_merkle_verify(rest: &str) -> String {
    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return "ERROR Need: leaf_hex siblings|directions root_hex".to_string();
    }

    let leaf = match hex_to_array(parts[0]) { Ok(a) => a, Err(e) => return e };
    let root = match hex_to_array(parts[2]) { Ok(a) => a, Err(e) => return e };

    let halves: Vec<&str> = parts[1].split('|').collect();
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
        match hex_to_array(sh) { Ok(a) => siblings.push(a), Err(e) => return e }
    }

    let proof = merkle::MerkleProof {
        leaf_hash: leaf,
        leaf_index: 0,
        siblings,
        directions,
        root,
    };

    format!("OK {}", merkle::MerkleIndex::verify_proof(&proof))
}

// ── Minimal JSON parser (no serde dependency — keeps binary small) ──

mod serde_json_minimal {
    pub struct Value {
        raw: String,
    }

    impl Value {
        /// Find the value start position for a key, handling optional spaces after colon
        fn find_value_start(&self, key: &str) -> Option<usize> {
            let key_pattern = format!(r#""{}""#, key);
            let key_pos = self.raw.find(&key_pattern)?;
            let after_key = key_pos + key_pattern.len();
            // Skip optional whitespace and colon
            let rest = &self.raw[after_key..];
            let colon_pos = rest.find(':')?;
            let after_colon = after_key + colon_pos + 1;
            // Skip whitespace after colon
            let rest2 = &self.raw[after_colon..];
            let trimmed = rest2.trim_start();
            Some(after_colon + (rest2.len() - trimmed.len()))
        }

        pub fn get_str<'a>(&'a self, key: &str) -> Option<&'a str> {
            let start = self.find_value_start(key)?;
            let rest = &self.raw[start..];
            if !rest.starts_with('"') { return None; }
            let inner = &rest[1..];
            let end = inner.find('"')?;
            Some(&inner[..end])
        }

        pub fn get_f64(&self, key: &str) -> Option<f64> {
            let start = self.find_value_start(key)?;
            let rest = &self.raw[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        }

        pub fn get_str_array(&self, key: &str) -> Vec<String> {
            let start = match self.find_value_start(key) {
                Some(s) => s,
                None => return Vec::new(),
            };
            let rest = &self.raw[start..];
            if !rest.starts_with('[') { return Vec::new(); }
            let inner = &rest[1..];
            let end = match inner.find(']') {
                Some(e) => e,
                None => return Vec::new(),
            };
            inner[..end].split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
    }

    pub fn parse(raw: &str) -> Result<Value, String> {
        if !raw.starts_with('{') || !raw.ends_with('}') {
            return Err("Not a JSON object".into());
        }
        Ok(Value { raw: raw.to_string() })
    }
}

fn parse_json_value(s: &str) -> Result<serde_json_minimal::Value, String> {
    serde_json_minimal::parse(s)
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

// ── Input validation ──

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() { return Err("ERROR Empty path".to_string()); }
    if path.contains('\n') || path.contains('\r') || path.contains('\0') || path.contains(' ') {
        return Err("ERROR Invalid path".to_string());
    }
    if path.contains("..") { return Err("ERROR Path traversal not allowed".to_string()); }
    Ok(())
}

fn canonicalize_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = Path::new(path);
    if p.exists() {
        let canonical = fs::canonicalize(p).map_err(|_| "ERROR Cannot resolve path".to_string())?;
        let meta = fs::symlink_metadata(p).map_err(|_| "ERROR Cannot stat path".to_string())?;
        if meta.file_type().is_symlink() { return Err("ERROR Symlinks not allowed".to_string()); }
        return Ok(canonical);
    }
    if let Some(parent) = p.parent() {
        if parent.as_os_str().is_empty() || parent.exists() { return Ok(p.to_path_buf()); }
    }
    Err("ERROR Path does not exist".to_string())
}

fn validate_tier(tier: &str) -> Result<(), String> {
    match tier {
        "warm" | "cold" | "frozen" | "hot" | "test" | "index" => Ok(()),
        _ => Err("ERROR Invalid tier".to_string()),
    }
}

fn hex_to_array(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 { return Err("ERROR Expected 64-char hex".to_string()); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Encrypt / Decrypt / Keygen (unchanged) ──

fn handle_encrypt(input: &str, output: &str, tier: &str) -> String {
    let input_path = match canonicalize_path(input) { Ok(p) => p, Err(e) => return e };
    let pubkey_hex = match keychain::get_public_key(tier) { Ok(k) => k, Err(e) => return format!("ERROR {}", e) };
    let pubkey_bytes = match hex::decode(&pubkey_hex) { Ok(b) => b, Err(_) => return "ERROR Invalid public key".to_string() };
    let meta = match fs::metadata(&input_path) { Ok(m) => m, Err(e) => return format!("ERROR {}", e) };
    if meta.len() > MAX_FILE_SIZE { return "ERROR Input file too large".to_string(); }
    let mut plaintext = match fs::read(&input_path) { Ok(d) => d, Err(e) => return format!("ERROR {}", e) };
    let result = crypto::encrypt(&pubkey_bytes, &plaintext);
    plaintext.zeroize();
    match result {
        Ok(encrypted) => {
            match fs::write(output, &encrypted) {
                Ok(_) => {
                    #[cfg(unix)] {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(output, fs::Permissions::from_mode(0o600));
                    }
                    "OK".to_string()
                }
                Err(e) => format!("ERROR {}", e),
            }
        }
        // Fix #18: generic error message (don't leak which step failed)
        Err(_) => "ERROR Encryption failed".to_string(),
    }
}

fn handle_decrypt(input: &str, output: &str, tier: &str) -> String {
    let input_path = match canonicalize_path(input) { Ok(p) => p, Err(e) => return e };
    let mut privkey_hex = match keychain::get_private_key(tier) { Ok(k) => k, Err(_) => return "ERROR Decryption failed".to_string() };
    let mut privkey_bytes = match hex::decode(&privkey_hex) {
        Ok(b) => b,
        Err(_) => { privkey_hex.zeroize(); return "ERROR Decryption failed".to_string(); }
    };
    privkey_hex.zeroize();
    let meta = match fs::metadata(&input_path) { Ok(m) => m, Err(_) => { privkey_bytes.zeroize(); return "ERROR Decryption failed".to_string(); } };
    if meta.len() > MAX_FILE_SIZE { privkey_bytes.zeroize(); return "ERROR Input file too large".to_string(); }
    let ciphertext = match fs::read(&input_path) { Ok(d) => d, Err(_) => { privkey_bytes.zeroize(); return "ERROR Decryption failed".to_string(); } };
    let result = crypto::decrypt(&privkey_bytes, &ciphertext);
    privkey_bytes.zeroize();
    match result {
        Ok(mut plaintext) => {
            let write_result = fs::write(output, &plaintext);
            plaintext.zeroize();
            match write_result {
                Ok(_) => {
                    #[cfg(unix)] {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(output, fs::Permissions::from_mode(0o600));
                    }
                    "OK".to_string()
                }
                Err(_) => "ERROR Decryption failed".to_string(),
            }
        }
        // Fix #18: generic error for all decrypt failures
        Err(_) => "ERROR Decryption failed".to_string(),
    }
}

fn handle_keygen(tier: &str) -> String {
    if keychain::get_private_key(tier).is_ok() {
        return format!("ERROR Key already exists for tier '{}'", tier);
    }
    let (privkey_bytes, pubkey_bytes) = crypto::generate_keypair();
    let pubkey_hex = hex::encode(&pubkey_bytes);
    let mut privkey_hex = hex::encode(&privkey_bytes);
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

// ── Hex (no external dep) ──

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 { return Err("Odd hex length".to_string()); }
        (0..hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex".to_string()))
            .collect()
    }
}

// ── libc ──

#[cfg(unix)]
mod libc {
    #[repr(C)]
    pub struct rlimit { pub rlim_cur: u64, pub rlim_max: u64 }
    pub const RLIMIT_CORE: i32 = 4;
    pub const MCL_CURRENT: i32 = 1;
    pub const MCL_FUTURE: i32 = 2;
    extern "C" {
        pub fn mlockall(flags: i32) -> i32;
        pub fn setrlimit(resource: i32, rlp: *const rlimit) -> i32;
    }
}
