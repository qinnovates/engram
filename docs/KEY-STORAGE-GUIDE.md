# Key Storage Guide

## Table of Contents

- [How keys work in Engram](#how-keys-work-in-engram)
- [Setup](#setup)
- [Supported key sources](#supported-key-sources)
  - [macOS Keychain](#macos-keychain)
  - [External command (Vault, KMS, custom)](#external-command-vault-kms-custom)
  - [Environment variable (CI/CD only)](#environment-variable-cicd-only)
  - [YubiKey / FIDO2 (hardware-bound, most secure)](#yubikey-fido2-hardware-bound-most-secure)
  - [File-based keys](#file-based-keys)
- [Security notes](#security-notes)
- [Risk comparison](#risk-comparison)

---

## How keys work in Engram

Engram uses a compiled Rust sidecar (`engram-vault`) for all private key operations. Private keys never enter Python, never touch disk as files, and never appear in terminal output or process arguments.

The sidecar retrieves keys from your configured source, holds them in locked memory, pipes them to `age` via stdin, and zeros them immediately after.

---

## Setup

```bash
# Generate per-tier keypairs, store directly in macOS Keychain
engram encrypt-setup
```

Or via the sidecar directly:
```bash
echo "KEYGEN warm" | engram-vault
echo "KEYGEN cold" | engram-vault
```

Private keys go straight from `age-keygen` into the Keychain. They never exist as files.

---

## Supported key sources

Configure in `~/.engram/config.json`:

### macOS Keychain
```json
"warm_private_source": "keychain:engram:warm-key"
```
Sidecar reads from Keychain via Security.framework. Touch ID on Apple Silicon.

### External command (Vault, KMS, custom)
```json
"warm_private_source": "command:vault kv get -field=key secret/engram/warm"
```
Sidecar calls the command, captures key from stdout, uses it, zeros it. The command must output only the key.

### Environment variable (CI/CD only)
```json
"warm_private_source": "env:ENGRAM_WARM_KEY"
```
For ephemeral CI/CD runners only. Not for persistent machines.

### YubiKey / FIDO2 (hardware-bound, most secure)

The private key never leaves the YubiKey hardware. This is the most secure option available.

```bash
# Install the age YubiKey plugin
brew install age-plugin-yubikey

# Generate a YubiKey-backed identity
age-plugin-yubikey  # follow the prompts — key is generated ON the YubiKey

# The plugin outputs a recipient (public key) and an identity file
# The identity file does NOT contain the private key — it's a pointer
# to the key slot on the YubiKey. The private key never leaves hardware.
```

Configure in `config.json`:
```json
"warm_private_source": "command:age -d -i ~/.age/yubikey-identity.txt"
```

The sidecar calls `age` with the YubiKey identity. `age` talks to the YubiKey via the plugin. The private key stays on the hardware chip. Not in the sidecar's memory. Not in Python. Not on disk. Not anywhere except the YubiKey.

**Requires:** Physical YubiKey inserted during decrypt/recall operations. No YubiKey = no access to encrypted data. That's the point.

### File-based keys
**Blocked.** The `file:` source raises an error. Keys must not exist as files on disk.

---

## Security notes

- macOS Keychain is software keychain, not Secure Enclave. Keys are extractable by processes running as your user.
- If you lose your private key, encrypted data is unrecoverable. No backdoor, no reset.
- Key rotation re-wraps envelope headers in O(metadata), not O(data).
- For shared machines, consider running encryption under a dedicated service account with RBAC.

---

## Risk comparison

| Source | Key on Disk | Key in Memory | Key in Python | Automation |
|--------|-----------|--------------|--------------|-----------|
| YubiKey/FIDO2 | No | No (hardware) | No | Physical key required |
| Keychain (macOS) | No | Sidecar only (mlock'd) | No | Touch ID |
| Command (Vault/KMS) | No | Sidecar only (mlock'd) | No | Yes |
| Environment | No | Process env | No | Yes |
| File | Blocked | — | — | — |
