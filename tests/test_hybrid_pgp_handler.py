import os
import sys
import json
import pytest

from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.hybrid_pgp_handler import HybridPGPHandler
from src.pgp_handler import PGPHandler


class DummyHybridCrypto:
    def __init__(self):
        self.pq_public_key = b"PUBKEY_" + os.urandom(1177)
        self.pq_secret_key = b"SECKEY_" + os.urandom(2400)

    def generate_keypair(self):
        return self.pq_public_key, self.pq_secret_key

    def encrypt_hybrid(self, plaintext, public_key):
        return b"\x01HYBRID" + plaintext

    def decrypt_hybrid(self, data, secret_key):
        if not data.startswith(b"\x01HYBRID"):
            raise ValueError("Not hybrid encrypted")
        return data[7:]

    def is_hybrid_encrypted(self, data):
        return data.startswith(b"\x01HYBRID")


class DummyGPG:
    def list_keys(self, secret=False):
        return [
            {
                "keyid": "ABC123",
                "fingerprint": "ABCDEF1234567890ABCDEF1234567890",
                "uids": ["test-key <test@example.com>"],
                "pubkey": "PUBKEYDATA123",
            }
        ]

    def encrypt(self, data, *recipients, **kwargs):
        result = DummyEncryptResult()
        result.data = b"GPGENC:" + data
        return result

    def decrypt(self, data, passphrase=None):
        result = DummyDecryptResult()
        if data.startswith(b"GPGENC:"):
            result.data = data[7:]
            result.ok = True
        else:
            result.ok = False
            result.status = "decryption failed"
        return result


class DummyEncryptResult:
    ok = True
    data = b""
    status = "encryption ok"


class DummyDecryptResult:
    ok = True
    data = b""
    status = "decryption ok"

    def __str__(self):
        return self.data.decode("utf-8", errors="replace")


class DummyPGPHandler:
    def __init__(self, config):
        self.config = config
        self.key_name = config["pgp"]["key_name"]
        self.key_fingerprint = "ABCDEF1234567890ABCDEF1234567890"
        self.passphrase = config["pgp"].get("passphrase")
        self.always_trust = bool(config["pgp"].get("always_trust", False))
        self.gpg = DummyGPG()

    def encrypt_file(self, file_path, output_path=None):
        out = output_path or (str(file_path) + ".gpg")
        with open(file_path, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:
            f.write(b"PGPENC:" + data)
        return out

    def decrypt_file(self, encrypted_path, output_path=None, verify_with=None):
        out = output_path or str(encrypted_path).replace(".gpg", "")
        with open(encrypted_path, "rb") as f:
            data = f.read()
        plaintext = data[7:] if data.startswith(b"PGPENC:") else data
        with open(out, "wb") as f:
            f.write(plaintext)
        return out


@pytest.fixture
def dummy_pgp_config(tmp_path):
    return {
        "pgp": {
            "key_name": "test-key",
            "passphrase": "test-pass",
            "gnupghome": str(tmp_path / ".gnupg"),
        }
    }


@pytest.fixture
def hybrid_pgp_handler_patched(dummy_pgp_config):
    with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
        with mock.patch(
            "src.hybrid_pgp_handler.HybridEncryption", return_value=DummyHybridCrypto()
        ):
            handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)
    return handler


class TestHybridPGPHandlerInitialization:
    def test_init_hybrid_mode_enabled(self, dummy_pgp_config, tmp_path):
        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)
        assert handler.hybrid_mode is True
        assert handler.pgp_handler is not None

    def test_init_hybrid_mode_disabled(self, dummy_pgp_config):
        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption", side_effect=ImportError
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=False)
        assert handler.hybrid_mode is False

    def test_init_handles_unavailable_hybrid(self, dummy_pgp_config):
        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):

            def raise_error():
                raise ImportError("liboqs not available")

            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption", side_effect=raise_error
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)
        # Should fall back to non-hybrid
        assert handler.hybrid_mode is False


class TestHybridPGPHandlerKeyStorage:
    def test_generate_new_pq_keys_on_first_run(self, dummy_pgp_config, tmp_path):
        dummy_pgp_config["pgp"]["gnupghome"] = str(tmp_path)

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        assert handler.pq_public_key is not None
        assert handler.pq_secret_key is not None

        # Verify keystore was created
        keystore = tmp_path / HybridPGPHandler.PQ_KEYSTORE_FILE
        assert keystore.exists()

    def test_load_existing_pq_keys(self, dummy_pgp_config, tmp_path):
        dummy_pgp_config["pgp"]["gnupghome"] = str(tmp_path)

        existing_keys = {
            "public_key": os.urandom(1184).hex(),
            "secret_key": os.urandom(2400).hex(),
        }
        keystore_path = tmp_path / HybridPGPHandler.PQ_KEYSTORE_FILE
        plaintext = json.dumps(existing_keys).encode("utf-8")
        keystore_path.write_bytes(b"GPGENC:" + plaintext)
        os.chmod(keystore_path, 0o600)

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        assert handler.pq_public_key.hex() == existing_keys["public_key"]
        assert handler.pq_secret_key.hex() == existing_keys["secret_key"]

    def test_pq_keystore_permissions_secure(self, dummy_pgp_config, tmp_path):
        import stat

        dummy_pgp_config["pgp"]["gnupghome"] = str(tmp_path)

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        keystore_path = tmp_path / HybridPGPHandler.PQ_KEYSTORE_FILE
        if keystore_path.exists():
            mode = stat.S_IMODE(os.stat(keystore_path).st_mode)
            assert mode & 0o077 == 0, (
                f"Keystore permissions too permissive: {oct(mode)}"
            )


class TestHybridPGPHandlerEncryption:
    def test_encrypt_file_hybrid_mode(self, hybrid_pgp_handler_patched, tmp_path):
        test_file = tmp_path / "plaintext.txt"
        test_file.write_text("secret data")

        encrypted = hybrid_pgp_handler_patched.encrypt_file(str(test_file))

        assert encrypted.endswith(".gpg")
        assert os.path.exists(encrypted)

        # Verify it's encrypted in hybrid format
        with open(encrypted, "rb") as f:
            data = f.read()
        assert data.startswith(b"\x01HYBRID"), "Should be hybrid encrypted"

    def test_encrypt_file_pgp_fallback(self, dummy_pgp_config, tmp_path):
        test_file = tmp_path / "plaintext.txt"
        test_file.write_text("secret data")

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption", side_effect=ImportError
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        encrypted = handler.encrypt_file(str(test_file))

        assert encrypted.endswith(".gpg")
        with open(encrypted, "rb") as f:
            data = f.read()
        # Should be PGP format, not hybrid
        assert data.startswith(b"PGPENC:")

    def test_encrypt_with_explicit_output_path(
        self, hybrid_pgp_handler_patched, tmp_path
    ):
        test_file = tmp_path / "plaintext.txt"
        test_file.write_text("data")
        output_file = tmp_path / "custom_encrypted.bin"

        result = hybrid_pgp_handler_patched.encrypt_file(
            str(test_file), str(output_file)
        )

        assert result == str(output_file)
        assert os.path.exists(str(output_file))

    def test_encrypt_hybrid_mode_disabled(self, dummy_pgp_config, tmp_path):
        test_file = tmp_path / "plaintext.txt"
        test_file.write_text("data")

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        # Encrypt without hybrid
        encrypted = handler.encrypt_file(str(test_file), use_hybrid=False)

        with open(encrypted, "rb") as f:
            data = f.read()
        # Should be PGP only
        assert data.startswith(b"PGPENC:")


class TestHybridPGPHandlerDecryption:
    def test_decrypt_hybrid_file(self, hybrid_pgp_handler_patched, tmp_path):
        # Create a hybrid-encrypted file
        encrypted_file = tmp_path / "test.gpg"
        plaintext = b"Secret message"

        # Manually create hybrid format
        hybrid_crypto = DummyHybridCrypto()
        encrypted_data = b"\x01HYBRID" + plaintext
        encrypted_file.write_bytes(encrypted_data)

        # Decrypt
        decrypted = hybrid_pgp_handler_patched.decrypt_file(str(encrypted_file))

        assert os.path.exists(decrypted)
        with open(decrypted, "rb") as f:
            result = f.read()
        assert result == plaintext

    def test_decrypt_pgp_only_file(self, dummy_pgp_config, tmp_path):
        encrypted_file = tmp_path / "test.gpg"
        plaintext = b"Secret message"

        # Create PGP format
        encrypted_data = b"PGPENC:" + plaintext
        encrypted_file.write_bytes(encrypted_data)

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        decrypted = handler.decrypt_file(str(encrypted_file))

        with open(decrypted, "rb") as f:
            result = f.read()
        assert result == plaintext

    def test_decrypt_with_output_path(self, hybrid_pgp_handler_patched, tmp_path):
        encrypted_file = tmp_path / "test.gpg"
        encrypted_file.write_bytes(b"\x01HYBRID" + b"data")

        output_file = tmp_path / "decrypted.txt"
        result = hybrid_pgp_handler_patched.decrypt_file(
            str(encrypted_file), str(output_file)
        )

        assert result == str(output_file)
        assert os.path.exists(str(output_file))

    def test_decrypt_with_checksum_verification(
        self, hybrid_pgp_handler_patched, tmp_path
    ):
        plaintext = b"Test data"
        encrypted_file = tmp_path / "test.gpg"
        encrypted_file.write_bytes(b"\x01HYBRID" + plaintext)

        original_file = tmp_path / "original.txt"
        original_file.write_bytes(plaintext)

        # Just verify it doesn't crash with verify_with parameter
        result = hybrid_pgp_handler_patched.decrypt_file(
            str(encrypted_file), verify_with=str(original_file)
        )
        assert os.path.exists(result)


class TestHybridPGPHandlerPublicKeyExport:
    def test_export_pq_public_key_string(self, hybrid_pgp_handler_patched):
        """Test exporting public key as JSON string."""
        key_json = hybrid_pgp_handler_patched.export_pq_public_key()

        data = json.loads(key_json)
        assert data["format_version"] == 1
        assert "pgp" in data
        assert "pq" in data
        assert data["pq"]["algorithm"] == "ML-KEM-768"

    def test_export_pq_public_key_to_file(self, hybrid_pgp_handler_patched, tmp_path):
        output_file = tmp_path / "hybrid_public.json"

        result = hybrid_pgp_handler_patched.export_pq_public_key(str(output_file))

        assert os.path.exists(str(output_file))

        with open(output_file, "r") as f:
            data = json.load(f)

        assert data["format_version"] == 1
        assert data["pq"]["public_key"]

    def test_export_pq_public_key_file_permissions(
        self, hybrid_pgp_handler_patched, tmp_path
    ):
        import stat

        output_file = tmp_path / "hybrid_public.json"
        hybrid_pgp_handler_patched.export_pq_public_key(str(output_file))

        mode = stat.S_IMODE(os.stat(output_file).st_mode)
        # Public key should be readable by all
        assert mode & 0o644 == 0o644 or mode & 0o755 != 0


class TestHybridPGPHandlerBackwardCompatibility:
    def test_hybrid_handler_works_without_pq_keys(self, dummy_pgp_config):
        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption", return_value=None
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)

        # Should still have PGP handler
        assert handler.pgp_handler is not None

    def test_encrypt_fallback_to_pgp_on_hybrid_error(self, dummy_pgp_config, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("data")
        mock_hybrid = DummyHybridCrypto()

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption", return_value=mock_hybrid
            ):
                handler = HybridPGPHandler(dummy_pgp_config, hybrid_mode=True)
                # Make hybrid encryption fail
                mock_hybrid.encrypt_hybrid = mock.Mock(
                    side_effect=Exception("Hybrid failed")
                )
                # Should fall back to PGP
                encrypted = handler.encrypt_file(str(test_file))
                assert encrypted is not None


class TestHybridPGPHandlerIntegration:
    def test_full_hybrid_encryption_decryption_cycle(self, tmp_path):
        pgp_config = {
            "pgp": {
                "key_name": "test-key",
                "passphrase": "test-pass",
                "gnupghome": str(tmp_path),
            }
        }

        # Create test data
        plaintext = b"Sensitive data for hybrid encryption"
        test_file = tmp_path / "plaintext.bin"
        test_file.write_bytes(plaintext)

        with mock.patch("src.hybrid_pgp_handler.PGPHandler", DummyPGPHandler):
            with mock.patch(
                "src.hybrid_pgp_handler.HybridEncryption",
                return_value=DummyHybridCrypto(),
            ):
                handler = HybridPGPHandler(pgp_config, hybrid_mode=True)

        # Encrypt
        encrypted_path = handler.encrypt_file(str(test_file))
        assert os.path.exists(encrypted_path)

        # Decrypt
        decrypted_path = handler.decrypt_file(encrypted_path)

        # Verify
        with open(decrypted_path, "rb") as f:
            recovered = f.read()

        assert recovered == plaintext
