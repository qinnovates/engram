"""Tests for asymmetric envelope encryption."""

import json
import os
from pathlib import Path

import pytest

from src.envelope import (
    generate_dek,
    EnvelopeHeader,
    EnvelopeEncryptor,
    AsymmetricKeyConfig,
    TierKeyPair,
    DEK_SIZE,
    ENVELOPE_HEADER_EXT,
    _resolve_private_key,
)
from src.encryption import EncryptionError


class TestDEKGeneration:
    def test_length(self):
        dek = generate_dek()
        assert len(dek) == DEK_SIZE

    def test_unique(self):
        assert generate_dek() != generate_dek()

    def test_bytes_type(self):
        dek = generate_dek()
        assert isinstance(dek, bytes)


class TestEnvelopeHeader:
    def test_json_roundtrip(self):
        header = EnvelopeHeader(
            tier="warm",
            encrypted_dek_hex="aabbccdd",
            plaintext_hash="deadbeef",
            artifact_path="/test/file.jsonl",
            key_generation=2,
        )
        restored = EnvelopeHeader.from_json(header.to_json())
        assert restored.tier == "warm"
        assert restored.encrypted_dek_hex == "aabbccdd"
        assert restored.plaintext_hash == "deadbeef"
        assert restored.key_generation == 2

    def test_unknown_fields_ignored(self):
        data = json.dumps({
            "version": 2, "tier": "cold",
            "encrypted_dek_hex": "ff",
            "future_field": "dropped",
        })
        header = EnvelopeHeader.from_json(data)
        assert header.tier == "cold"

    def test_version(self):
        header = EnvelopeHeader()
        assert header.version == 2  # Asymmetric version


class TestResolvePrivateKey:
    def test_file_source_rejected(self):
        """file: source must be rejected — private keys should never be on disk."""
        with pytest.raises(EncryptionError, match="not supported"):
            _resolve_private_key("file:/some/path/key.txt")

    def test_env_source(self):
        os.environ["TEST_TM_PRIVKEY"] = "AGE-SECRET-KEY-1TESTKEY"
        try:
            result = _resolve_private_key("env:TEST_TM_PRIVKEY")
            assert result == "AGE-SECRET-KEY-1TESTKEY"
        finally:
            del os.environ["TEST_TM_PRIVKEY"]

    def test_env_source_missing(self):
        with pytest.raises(EncryptionError, match="not set"):
            _resolve_private_key("env:NONEXISTENT_VAR_12345")

    def test_env_invalid_var_name(self):
        with pytest.raises(EncryptionError, match="Invalid environment variable"):
            _resolve_private_key("env:not-a-valid-var!")

    def test_empty_source_raises(self):
        with pytest.raises(EncryptionError, match="No private key source"):
            _resolve_private_key("")

    def test_unknown_source_raises(self):
        with pytest.raises(EncryptionError, match="Unknown"):
            _resolve_private_key("ftp://something")

    def test_command_source(self):
        result = _resolve_private_key("command:echo AGE-SECRET-KEY-1TEST")
        assert result == "AGE-SECRET-KEY-1TEST"

    def test_command_source_failure(self):
        with pytest.raises(EncryptionError, match="failed"):
            _resolve_private_key("command:false")


class TestAsymmetricKeyConfig:
    def test_defaults(self):
        config = AsymmetricKeyConfig()
        assert config.enabled is False
        assert config.warm.pubkey == ""
        assert config.cold.pubkey == ""

    def test_get_tier_keys(self):
        config = AsymmetricKeyConfig(
            warm=TierKeyPair(pubkey="age1warmkey"),
            cold=TierKeyPair(pubkey="age1coldkey"),
        )
        assert config.get_tier_keys("warm").pubkey == "age1warmkey"
        assert config.get_tier_keys("cold").pubkey == "age1coldkey"

    def test_unknown_tier_raises(self):
        config = AsymmetricKeyConfig()
        with pytest.raises(ValueError, match="Unknown tier"):
            config.get_tier_keys("frozen")


class TestEnvelopeEncryptorIntegration:
    """
    Integration tests that require age to be installed.
    These test the full asymmetric encrypt/decrypt cycle.
    """

    @pytest.fixture
    def age_keypair(self) -> tuple[str, str]:
        """Generate a real keypair for testing via sidecar."""
        import shutil
        vault_bin = shutil.which("engram-vault")
        if not vault_bin:
            pytest.skip("engram-vault sidecar not installed")
        try:
            pubkey = EnvelopeEncryptor.generate_tier_keypair("test")
        except Exception:
            pytest.skip("Keypair generation failed (may already exist)")
        return pubkey, "keychain:engram:test-key"

    @pytest.fixture
    def sample_artifact(self, tmp_path: Path) -> Path:
        f = tmp_path / "test-session.jsonl"
        lines = [f'{{"turn": {i}, "text": "content {i}"}}\n' for i in range(50)]
        f.write_text("".join(lines))
        return f

    def test_create_envelope_pubkey_only(self, age_keypair, sample_artifact):
        """Encryption uses ONLY the public key — no private key needed."""
        pubkey, _ = age_keypair

        config = AsymmetricKeyConfig(
            enabled=True,
            warm=TierKeyPair(
                pubkey=pubkey,
                private_key_source="",  # Not needed for encryption!
            ),
        )
        enc = EnvelopeEncryptor(config)
        header, dek = enc.create_envelope(sample_artifact, "warm")

        assert header.tier == "warm"
        assert header.encrypted_dek_hex  # DEK was encrypted
        assert header.plaintext_hash  # Hash was computed
        assert len(dek) == DEK_SIZE

    def test_full_encrypt_decrypt_cycle(self, age_keypair, sample_artifact, tmp_path):
        """Full roundtrip: encrypt DEK with pubkey, decrypt with privkey."""
        pubkey, privkey = age_keypair

        # Store private key in env for testing
        os.environ["TEST_TM_WARM_KEY"] = privkey

        try:
            config = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(
                    pubkey=pubkey,
                    private_key_source="env:TEST_TM_WARM_KEY",
                ),
            )
            enc = EnvelopeEncryptor(config)

            # Encrypt (public key only)
            header, dek = enc.create_envelope(sample_artifact, "warm")

            # Decrypt (needs private key)
            recovered_dek = enc.recover_dek(header)

            assert recovered_dek == dek
        finally:
            del os.environ["TEST_TM_WARM_KEY"]

    def test_different_artifacts_different_deks(self, age_keypair, tmp_path):
        """Each artifact gets its own unique DEK."""
        pubkey, _ = age_keypair

        config = AsymmetricKeyConfig(
            enabled=True,
            warm=TierKeyPair(pubkey=pubkey),
        )
        enc = EnvelopeEncryptor(config)

        f1 = tmp_path / "a.jsonl"
        f1.write_text("file 1")
        f2 = tmp_path / "b.jsonl"
        f2.write_text("file 2")

        _, dek1 = enc.create_envelope(f1, "warm")
        _, dek2 = enc.create_envelope(f2, "warm")

        assert dek1 != dek2

    def test_wrong_private_key_fails(self, sample_artifact):
        """Decrypting with wrong private key must fail."""
        pytest.skip("Requires sidecar integration test rewrite (age removed)")

        # Generate two different keypairs
        pub1, priv1 = EnvelopeEncryptor.generate_tier_keypair()
        pub2, priv2 = EnvelopeEncryptor.generate_tier_keypair()

        os.environ["TEST_TM_WRONG_KEY"] = priv2

        try:
            # Encrypt with keypair 1
            config1 = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(pubkey=pub1),
            )
            enc1 = EnvelopeEncryptor(config1)
            header, _ = enc1.create_envelope(sample_artifact, "warm")

            # Try to decrypt with keypair 2's private key — must fail
            config2 = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(
                    pubkey=pub2,
                    private_key_source="env:TEST_TM_WRONG_KEY",
                ),
            )
            enc2 = EnvelopeEncryptor(config2)
            with pytest.raises(EncryptionError, match="wrong key|Failed"):
                enc2.recover_dek(header)
        finally:
            del os.environ["TEST_TM_WRONG_KEY"]

    def test_warm_cold_separate_keypairs(self, sample_artifact):
        """Warm and cold tiers use independent keypairs."""
        pytest.skip("Requires sidecar integration test rewrite (age removed)")

        warm_pub, warm_priv = EnvelopeEncryptor.generate_tier_keypair()
        cold_pub, cold_priv = EnvelopeEncryptor.generate_tier_keypair()

        os.environ["TEST_TM_WARM"] = warm_priv
        os.environ["TEST_TM_COLD"] = cold_priv

        try:
            config = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(pubkey=warm_pub, private_key_source="env:TEST_TM_WARM"),
                cold=TierKeyPair(pubkey=cold_pub, private_key_source="env:TEST_TM_COLD"),
            )
            enc = EnvelopeEncryptor(config)

            # Encrypt same artifact for both tiers
            header_warm, dek_warm = enc.create_envelope(sample_artifact, "warm")
            header_cold, dek_cold = enc.create_envelope(sample_artifact, "cold")

            # Each tier can decrypt its own
            assert enc.recover_dek(header_warm) == dek_warm
            assert enc.recover_dek(header_cold) == dek_cold

            # DEKs are unique per operation
            assert dek_warm != dek_cold

        finally:
            del os.environ["TEST_TM_WARM"]
            del os.environ["TEST_TM_COLD"]

    def test_key_rotation(self, sample_artifact, tmp_path):
        """Key rotation re-wraps DEKs without touching data."""
        pytest.skip("Requires sidecar integration test rewrite (age removed)")

        old_pub, old_priv = EnvelopeEncryptor.generate_tier_keypair()
        new_pub, new_priv = EnvelopeEncryptor.generate_tier_keypair()

        os.environ["TEST_TM_OLD"] = old_priv
        os.environ["TEST_TM_NEW"] = new_priv

        headers_dir = tmp_path / "headers"
        headers_dir.mkdir()

        try:
            old_config = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(pubkey=old_pub, private_key_source="env:TEST_TM_OLD"),
                key_generation=1,
            )

            # Create envelopes with old key
            enc = EnvelopeEncryptor(old_config)
            original_deks = []
            for i in range(3):
                header, dek = enc.create_envelope(sample_artifact, "warm")
                (headers_dir / f"artifact-{i}{ENVELOPE_HEADER_EXT}").write_text(
                    header.to_json()
                )
                original_deks.append(dek)

            # Rotate to new key
            new_config = AsymmetricKeyConfig(
                enabled=True,
                warm=TierKeyPair(pubkey=new_pub, private_key_source="env:TEST_TM_NEW"),
                key_generation=2,
            )
            rotated = enc.rotate_keys(headers_dir, new_config)
            assert rotated == 3

            # Verify new key works
            enc_new = EnvelopeEncryptor(new_config)
            for i, header_file in enumerate(
                sorted(headers_dir.glob(f"*{ENVELOPE_HEADER_EXT}"))
            ):
                header = EnvelopeHeader.from_json(header_file.read_text())
                assert header.key_generation == 2
                dek = enc_new.recover_dek(header)
                assert dek == original_deks[i]

        finally:
            del os.environ["TEST_TM_OLD"]
            del os.environ["TEST_TM_NEW"]
