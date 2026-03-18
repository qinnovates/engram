# Key Storage Guide

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

| Source | Key on Disk | Key in Args | Key in Python | Automation |
|--------|-----------|------------|--------------|-----------|
| Keychain | No | No | No | Touch ID |
| Command (Vault/KMS) | No | No | No | Yes |
| Environment | No | No | No | Yes |
| File | Blocked | — | — | — |
