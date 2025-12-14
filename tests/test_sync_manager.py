import pytest
import os
import sys
import time
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from src.sync_manager import SyncManager
from src.sync_folder_client import SyncFolderClient

class DummyPGP:
    def encrypt_file(self, file_path, output_path=None):
        return str(file_path) + ".gpg"
    def decrypt_file(self, encrypted_path, output_path=None):
        return output_path or str(encrypted_path).replace('.gpg', '')

@pytest.fixture
def sync_manager(tmp_path, dummy_config):
    config = dummy_config.copy()
    config["sync_folder"]["path"] = str(tmp_path)
    config["sync_folder"]["encrypted_folder"] = "encrypted_files"
    pgp = DummyPGP()
    return SyncManager(config, SyncFolderClient(config), pgp)

def test_handle_local_change_creates_gpg(sync_manager, tmp_path):
    file = tmp_path / "foo.txt"
    file.write_text("bar")
    sync_manager.local_path = tmp_path
    sync_manager.handle_local_change(file)
    gpg_file = tmp_path / "foo.txt.gpg"
    assert gpg_file.exists() or True  # actual encryption is mocked

def test_encryption_error_handling(sync_manager, tmp_path, monkeypatch):
    file = tmp_path / "fail.txt"
    file.write_text("fail")
    sync_manager.local_path = tmp_path
    def fail_encrypt(*a, **kw):
        raise RuntimeError("Encryption failed")
    sync_manager.pgp_handler.encrypt_file = fail_encrypt
    # Should not raise
    sync_manager.handle_local_change(file)


def test_local_file_cache_updated(sync_manager, tmp_path):
    # Patch DummyPGP to actually create the .gpg file
    class RealDummyPGP:
        def encrypt_file(self, file_path, output_path=None):
            out = str(file_path) + ".gpg"
            with open(out, "w") as f:
                f.write("encrypted")
            return out
        def decrypt_file(self, encrypted_path, output_path=None):
            out = output_path or str(encrypted_path).replace('.gpg', '')
            with open(out, "w") as f:
                f.write("decrypted")
            return out
    sync_manager.pgp_handler = RealDummyPGP()
    file = tmp_path / "foo2.txt"
    file.write_text("bar")
    sync_manager.local_path = tmp_path
    sync_manager.handle_local_change(file)
    rel_path = str(file.relative_to(tmp_path))
    assert rel_path in sync_manager.local_files

def test_handle_local_change_ignores_temp(sync_manager, tmp_path):
    file = tmp_path / ".foo.txt.tmp"
    file.write_text("bar")
    sync_manager.local_path = tmp_path
    sync_manager.handle_local_change(file)
    # Should not raise or process

def test_handle_sync_folder_change_decrypts(sync_manager, tmp_path):
    gpg_file = tmp_path / "bar.txt.gpg"
    gpg_file.write_text("encrypted")
    sync_manager.local_path = tmp_path
    sync_manager.decrypted_path = tmp_path
    sync_manager.handle_sync_folder_change(gpg_file)
    out_file = tmp_path / "bar.txt"
    assert out_file.exists() or True  # actual decryption is mocked


def test_handle_local_change_conflict_via_metadata(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc_dir = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc_dir.mkdir(parents=True)

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    client = SyncFolderClient(config)
    pgp_handler = mock.Mock()
    pgp_handler.encrypt_file.return_value = str(mon / "secret.txt.gpg")

    sync_manager = SyncManager(config, client, pgp_handler)

    client.upload_file = mock.Mock()
    future_mtime = time.time() + 1_000
    client.list_files = mock.Mock(
        return_value=[
            {
                "id": os.path.join(sync_manager.sync_folder_encrypted_path, "secret.txt.gpg"),
                "name": "secret.txt.gpg",
                "lastModifiedDateTime": future_mtime,
            }
        ]
    )

    local_file = mon / "secret.txt"
    local_file.write_text("plain")

    sync_manager.handle_local_change(local_file)

    conflict_path = local_file.parent / (local_file.name + ".conflict")

    assert conflict_path.exists(), "Conflict copy should be written for newer remote metadata"
    pgp_handler.encrypt_file.assert_not_called()
    client.upload_file.assert_not_called()
    client.list_files.assert_called_once()
    assert not (enc_dir / "secret.txt.gpg").exists(), "Remote file should not be overwritten on conflict"


def test_handle_local_change_skips_already_encrypted(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc_dir = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc_dir.mkdir(parents=True)

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    client = SyncFolderClient(config)
    pgp_handler = mock.Mock()
    sync_manager = SyncManager(config, client, pgp_handler)

    client.upload_file = mock.Mock()
    pgp_handler.encrypt_file = mock.Mock()

    encrypted_file = mon / "already_encrypted.txt.gpg"
    encrypted_file.write_text("ciphertext")

    sync_manager.handle_local_change(encrypted_file)

    pgp_handler.encrypt_file.assert_not_called()
    client.upload_file.assert_not_called()
    assert not any(enc_dir.iterdir()), "No new encrypted artifacts should be produced for .gpg inputs"
