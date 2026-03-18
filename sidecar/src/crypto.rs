//! Cryptographic operations — NIST-approved algorithms only.
//!
//! Algorithms:
//!   ML-KEM-768 (FIPS 203) — post-quantum key encapsulation
//!   AES-256-GCM (FIPS 197 + SP 800-38D) — authenticated encryption
//!   HKDF-SHA256 (SP 800-56C) — key derivation
//!   X25519 — classical key agreement (hybrid with ML-KEM)
//!
//! No external binaries. No outbound calls. All crypto in-process.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"ENCF";
const VERSION: u16 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HKDF_INFO: &[u8] = b"engram-vault-v2-nist";
const GCM_TAG_LEN: usize = 16;

// ML-KEM-768 key types
type DkType = <MlKem768 as KemCore>::DecapsulationKey;
type EkType = <MlKem768 as KemCore>::EncapsulationKey;

// Minimum valid public key length: ML-KEM-768 EK (1184) + X25519 (32)
const MIN_PUBKEY_LEN: usize = 1216;

/// Generate a hybrid ML-KEM-768 + X25519 keypair.
/// Returns (private_key_bytes, public_key_bytes).
/// Private key is wrapped in Zeroizing for automatic cleanup.
pub fn generate_keypair() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    // ML-KEM-768 keypair
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let dk_encoded: Encoded<DkType> = dk.as_bytes();
    let ek_encoded: Encoded<EkType> = ek.as_bytes();

    // X25519 keypair
    let x_secret = StaticSecret::random_from_rng(&mut OsRng);
    let x_public = PublicKey::from(&x_secret);

    // Private: [dk_encoded | x25519_secret_32] — Zeroizing wrapper
    let mut privkey = Zeroizing::new(dk_encoded.to_vec());
    privkey.extend_from_slice(x_secret.as_bytes());

    // Public: [ek_encoded | x25519_public_32]
    let mut pubkey = ek_encoded.to_vec();
    pubkey.extend_from_slice(x_public.as_bytes());

    (privkey, pubkey)
}

/// Encrypt plaintext with a hybrid public key. Returns .encf formatted bytes.
pub fn encrypt(pubkey_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if pubkey_bytes.len() < MIN_PUBKEY_LEN {
        return Err("Public key too short".to_string());
    }

    // Split public key: [ek_bytes | x25519_public_32]
    let ek_len = pubkey_bytes.len() - 32;
    let ek_bytes = &pubkey_bytes[..ek_len];
    let x_pk_bytes: [u8; 32] = pubkey_bytes[ek_len..]
        .try_into()
        .map_err(|_| "Bad X25519 public key")?;

    // ML-KEM encapsulate
    let ek_array: Encoded<EkType> = ek_bytes
        .try_into()
        .map_err(|_| "Invalid encapsulation key length")?;
    let ek = EkType::from_bytes(&ek_array);
    let (ct_kem, ss_kem) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| "ML-KEM encapsulation failed")?;
    let ct_kem_bytes = ct_kem.as_slice();

    // X25519 ephemeral DH
    let eph = EphemeralSecret::random_from_rng(&mut OsRng);
    let eph_pub = PublicKey::from(&eph);
    let recipient_pk = PublicKey::from(x_pk_bytes);
    let ss_x25519 = eph.diffie_hellman(&recipient_pk);

    // HKDF: combine both shared secrets -> AES-256 key
    // Zeroizing wrappers ensure cleanup on ALL exit paths (including errors/panics)
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_kem.as_slice());
    ikm.extend_from_slice(ss_x25519.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut aes_key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, aes_key.as_mut())
        .map_err(|_| "HKDF failed")?;

    // AES-256-GCM encrypt
    let cipher =
        Aes256Gcm::new_from_slice(aes_key.as_ref()).map_err(|_| "AES init failed")?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "AES-GCM encrypt failed")?;

    // Build .encf file
    let pt_len = plaintext.len() as u64;
    let kem_ct_len = ct_kem_bytes.len() as u16;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&kem_ct_len.to_le_bytes());
    out.extend_from_slice(ct_kem_bytes);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&pt_len.to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an .encf file with a hybrid private key. Returns plaintext.
pub fn decrypt(privkey_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 8 || &data[0..4] != MAGIC {
        return Err("Invalid file format".to_string());
    }
    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != VERSION {
        return Err(format!("Unsupported version {}", version));
    }

    let kem_ct_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut pos = 8;

    if data.len() < pos + kem_ct_len + 32 + SALT_LEN + NONCE_LEN + 8 {
        return Err("File truncated".to_string());
    }

    let ct_kem_bytes = &data[pos..pos + kem_ct_len];
    pos += kem_ct_len;
    let eph_pk_bytes: [u8; 32] = data[pos..pos + 32]
        .try_into()
        .map_err(|_| "Bad ephemeral key")?;
    pos += 32;
    let salt = &data[pos..pos + SALT_LEN];
    pos += SALT_LEN;
    let nonce_bytes = &data[pos..pos + NONCE_LEN];
    pos += NONCE_LEN;
    let pt_len = u64::from_le_bytes(
        data[pos..pos + 8]
            .try_into()
            .map_err(|_| "Bad length")?,
    );
    pos += 8;
    let ciphertext = &data[pos..];

    // Validate pt_len against ciphertext (GCM adds 16-byte auth tag)
    let expected_ct_len = (pt_len as usize).checked_add(GCM_TAG_LEN)
        .ok_or("Plaintext length overflow")?;
    if ciphertext.len() != expected_ct_len {
        return Err("Ciphertext length mismatch".to_string());
    }

    // Split private key: [dk_bytes | x25519_secret_32]
    if privkey_bytes.len() < 32 {
        return Err("Private key too short".to_string());
    }
    let dk_len = privkey_bytes.len() - 32;
    let dk_bytes = &privkey_bytes[..dk_len];
    let x_secret_bytes: [u8; 32] = privkey_bytes[dk_len..]
        .try_into()
        .map_err(|_| "Bad X25519 private key")?;

    // ML-KEM decapsulate
    let dk_array: Encoded<DkType> = dk_bytes
        .try_into()
        .map_err(|_| "Invalid decapsulation key length")?;
    let dk = DkType::from_bytes(&dk_array);
    let ct_kem_array: ml_kem::Ciphertext<MlKem768> = ct_kem_bytes
        .try_into()
        .map_err(|_| "Invalid KEM ciphertext length")?;
    let ss_kem = dk
        .decapsulate(&ct_kem_array)
        .map_err(|_| "ML-KEM decapsulation failed")?;

    // X25519 DH
    let x_secret = StaticSecret::from(x_secret_bytes);
    let eph_pk = PublicKey::from(eph_pk_bytes);
    let ss_x25519 = x_secret.diffie_hellman(&eph_pk);

    // HKDF -> AES key (Zeroizing wrappers for all key material)
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_kem.as_slice());
    ikm.extend_from_slice(ss_x25519.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut aes_key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, aes_key.as_mut())
        .map_err(|_| "HKDF failed")?;

    // AES-256-GCM decrypt
    let cipher =
        Aes256Gcm::new_from_slice(aes_key.as_ref()).map_err(|_| "AES init failed")?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed")?;

    Ok(plaintext)
}
