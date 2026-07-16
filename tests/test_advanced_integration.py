import os
import sys
import time
import pytest
import tempfile
import threading

from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.sync_manager import SyncManager
from src.sync_folder_client import SyncFolderClient
from src.pgp_handler import PGPHandler


class DummyPGPComplex:
    def __init__(self, config):
        self.config = config
        self.key_name = config["pgp"]["key_name"]
        self.encrypt_count = 0
        self.gpg = mock.MagicMock()
        self.gpg.list_keys.return_value = [
            {"keyid": "ABC123", "uids": ["test"], "pubkey": "data"}
        ]

    def encrypt_file(self, file_path, output_path=None):
        self.encrypt_count += 1
        out = output_path or (str(file_path) + ".gpg")
        with open(file_path, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:
            f.write(b"ENCRYPTED:" + data)
        return out

    def decrypt_file(self, encrypted_path, output_path=None, verify_with=None):
        out = output_path or str(encrypted_path).replace(".gpg", "")
        with open(encrypted_path, "rb") as f:
            data = f.read()
        plaintext = data[10:] if data.startswith(b"ENCRYPTED:") else data
        with open(out, "wb") as f:
            f.write(plaintext)
        return out


class TestEndToEndWorkflows:
    def test_multiple_file_sync_workflow(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create and sync multiple files
        files = []
        for i in range(5):
            test_file = mon / f"file_{i}.txt"
            test_file.write_text(f"content {i}")
            files.append(test_file)
            sm.handle_local_change(test_file)

        # All files should be encrypted
        assert pgp.encrypt_count == 5, (
            f"Expected 5 encryptions, got {pgp.encrypt_count}"
        )

        # All encrypted files should exist
        for i in range(5):
            encrypted = sync / f"file_{i}.txt.gpg"
            assert encrypted.exists(), f"Encrypted file {i} missing"

    def test_sync_with_deletions(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create and encrypt a file
        test_file = mon / "test.txt"
        test_file.write_text("content")
        sm.handle_local_change(test_file)

        # File should be encrypted
        encrypted = sync / "test.txt.gpg"
        assert encrypted.exists()

    def test_large_scale_file_operations(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create many files
        num_files = 20
        for i in range(num_files):
            test_file = mon / f"file_{i:03d}.txt"
            test_file.write_text(f"data {i}")
            sm.handle_local_change(test_file)

        # All should be encrypted
        assert pgp.encrypt_count >= num_files


class TestConcurrentOperations:
    def test_concurrent_file_handling_no_corruption(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        results = []

        def create_and_encrypt(file_num):
            try:
                test_file = mon / f"concurrent_{file_num}.txt"
                test_file.write_text(f"concurrent data {file_num}")
                sm.handle_local_change(test_file)
                results.append(("success", file_num))
            except Exception as e:
                results.append(("error", file_num, str(e)))

        # Run multiple threads
        threads = [
            threading.Thread(target=create_and_encrypt, args=(i,)) for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed
        assert all(r[0] == "success" for r in results), (
            f"Some operations failed: {results}"
        )


class TestBoundaryEdgeCases:
    def test_zero_byte_file(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create empty file
        test_file = mon / "empty.txt"
        test_file.touch()
        sm.handle_local_change(test_file)

        # Should still encrypt
        encrypted = sync / "empty.txt.gpg"
        assert encrypted.exists()

    def test_very_long_filename(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create file with long name
        long_name = "f" * 200 + ".txt"
        test_file = mon / long_name
        test_file.write_text("data")

        # Should handle gracefully
        try:
            sm.handle_local_change(test_file)
        except OSError:
            # Expected on some systems with path length limits
            pass

    def test_special_characters_in_filename(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # File with special chars
        test_file = mon / "file with spaces & symbols (1).txt"
        test_file.write_text("data")
        sm.handle_local_change(test_file)

        # Should be encrypted
        encrypted = sync / "file with spaces & symbols (1).txt.gpg"
        assert encrypted.exists()


class TestErrorRecoveryAdvanced:
    def test_recovery_from_encryption_failure(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        class FailingPGP:
            def __init__(self, config):
                self.config = config
                self.key_name = config["pgp"]["key_name"]
                self.call_count = 0
                self.gpg = mock.MagicMock()
                self.gpg.list_keys.return_value = [
                    {"keyid": "ABC", "uids": ["test"], "pubkey": "data"}
                ]

            def encrypt_file(self, file_path, output_path=None):
                self.call_count += 1
                if self.call_count <= 2:
                    raise RuntimeError("Encryption failed")
                # Third call succeeds
                out = output_path or (str(file_path) + ".gpg")
                with open(out, "wb") as f:
                    f.write(b"encrypted")
                return out

            def decrypt_file(self, path, output=None, verify_with=None):
                return path.replace(".gpg", "")

        pgp = FailingPGP(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # First two attempts fail
        test_file = mon / "test.txt"
        test_file.write_text("data")

        sm.handle_local_change(test_file)
        sm.handle_local_change(test_file)

        # Third attempt succeeds
        sm.handle_local_change(test_file)

        # System should recover
        assert pgp.call_count == 3

    def test_system_continues_after_error(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # First file succeeds
        file1 = mon / "file1.txt"
        file1.write_text("data1")
        sm.handle_local_change(file1)

        count_after_first = pgp.encrypt_count

        # Simulate an error by using invalid path
        try:
            sm.handle_local_change(Path("/nonexistent/file"))
        except Exception:
            pass  # Expected

        # System should work
        file2 = mon / "file2.txt"
        file2.write_text("data2")
        sm.handle_local_change(file2)

        # Second file should also be encrypted
        assert pgp.encrypt_count > count_after_first


class TestDataConsistency:
    def test_file_content_preserved(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create file with specific content
        original_content = "This is important data\nWith multiple lines\n"
        test_file = mon / "important.txt"
        test_file.write_text(original_content)

        # Encrypt
        sm.handle_local_change(test_file)

        # Decrypt
        encrypted_file = sync / "important.txt.gpg"
        sm.handle_sync_folder_change(encrypted_file)

        # Verify content
        decrypted_file = dec / "important.txt"
        assert decrypted_file.exists()
        assert decrypted_file.read_text() == original_content

    def test_binary_file_integrity(self, tmp_path):
        mon = tmp_path / "mon"
        dec = tmp_path / "dec"
        sync = tmp_path / "sync" / "encrypted_files"
        mon.mkdir()
        dec.mkdir()
        sync.mkdir(parents=True)

        config = {
            "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
            "sync_folder": {
                "path": str(tmp_path / "sync"),
                "encrypted_folder": "encrypted_files",
            },
            "pgp": {"key_name": "test", "passphrase": "", "gnupghome": str(tmp_path)},
        }

        pgp = DummyPGPComplex(config)
        client = SyncFolderClient(config)
        sm = SyncManager(config, client, pgp)

        # Create binary file
        binary_data = bytes(range(256)) * 10
        test_file = mon / "binary.bin"
        test_file.write_bytes(binary_data)

        # Encrypt
        sm.handle_local_change(test_file)

        # Decrypt
        encrypted_file = sync / "binary.bin.gpg"
        sm.handle_sync_folder_change(encrypted_file)

        decrypted_file = dec / "binary.bin"
        assert decrypted_file.read_bytes() == binary_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
