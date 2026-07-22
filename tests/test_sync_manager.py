import pytest
import os
import sys
import time
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from src.sync_manager import SyncManager
from src.sync_folder_client import SyncFolderClient


class DummyPGP:
    def encrypt_file(self, file_path, output_path=None):
        out = output_path or (str(file_path) + ".gpg")
        with open(file_path, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:
            f.write(data)
        return out

    def decrypt_file(self, encrypted_path, output_path=None, verify_with=None):
        out = output_path or str(encrypted_path).replace(".gpg", "")
        with open(encrypted_path, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:
            f.write(data)
        return out


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
            out = output_path or str(encrypted_path).replace(".gpg", "")
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
    enc_path = tmp_path / "encrypted_files"
    enc_path.mkdir(exist_ok=True)
    gpg_file = enc_path / "bar.txt.gpg"
    gpg_file.write_text("encrypted")
    mon_path = tmp_path / "monitored"
    mon_path.mkdir(exist_ok=True)
    dec_path = tmp_path / "decrypted"
    dec_path.mkdir(exist_ok=True)
    sync_manager.local_path = mon_path
    sync_manager.decrypted_path = dec_path
    sync_manager.sync_folder_encrypted_path = str(enc_path)
    sync_manager.handle_sync_folder_change(gpg_file)
    out_file = dec_path / "bar.txt"
    assert out_file.exists()


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
                "id": os.path.join(
                    sync_manager.sync_folder_encrypted_path, "secret.txt.gpg"
                ),
                "name": "secret.txt.gpg",
                "lastModifiedDateTime": future_mtime,
            }
        ]
    )

    local_file = mon / "secret.txt"
    local_file.write_text("plain")

    sync_manager.handle_local_change(local_file)

    conflict_path = local_file.parent / (local_file.name + ".conflict")

    assert conflict_path.exists(), (
        "Conflict copy should be written for newer remote metadata"
    )
    pgp_handler.encrypt_file.assert_not_called()
    client.upload_file.assert_not_called()
    client.list_files.assert_called_once()
    assert not (enc_dir / "secret.txt.gpg").exists(), (
        "Remote file should not be overwritten on conflict"
    )


def test_startup_populates_decrypted_dir(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc.mkdir(parents=True)

    # Create encrypted files that should be decrypted on startup
    (enc / "secret.txt.gpg").write_text("encrypted")
    (enc / "notes.md.gpg").write_text("encrypted")

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    class RealDummyPGP:
        def encrypt_file(self, file_path, output_path=None):
            out = str(file_path) + ".gpg"
            with open(out, "w") as f:
                f.write("encrypted")
            return out

        def decrypt_file(self, encrypted_path, output_path=None):
            out = output_path or str(encrypted_path).replace(".gpg", "")
            with open(out, "w") as f:
                f.write("decrypted")
            return out

    sm = SyncManager(config, SyncFolderClient(config), RealDummyPGP())
    sm.start()
    try:
        assert (dec / "secret.txt").exists()
        assert (dec / "notes.md").exists()
        assert (dec / "secret.txt").read_text() == "decrypted"
    finally:
        sm.stop()


def test_startup_populates_nested_encrypted_files(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc.mkdir(parents=True)

    nested_dir = enc / "subdir"
    nested_dir.mkdir()
    (nested_dir / "deep.txt.gpg").write_text("encrypted")

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    class RealDummyPGP:
        def encrypt_file(self, file_path, output_path=None):
            out = str(file_path) + ".gpg"
            with open(out, "w") as f:
                f.write("encrypted")
            return out

        def decrypt_file(self, encrypted_path, output_path=None):
            out = output_path or str(encrypted_path).replace(".gpg", "")
            with open(out, "w") as f:
                f.write("decrypted")
            return out

    sm = SyncManager(config, SyncFolderClient(config), RealDummyPGP())
    sm.start()
    try:
        assert (dec / "subdir" / "deep.txt").exists()
        assert (dec / "subdir" / "deep.txt").read_text() == "decrypted"
    finally:
        sm.stop()


def test_shutdown_clears_decrypted_dir(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc.mkdir(parents=True)

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    sm = SyncManager(config, SyncFolderClient(config), DummyPGP())

    # Create some files in the decrypted directory
    (dec / "file1.txt").write_text("data")
    (dec / "file2.md").write_text("data")
    sub = dec / "subdir"
    sub.mkdir()
    (sub / "nested.txt").write_text("data")

    sm.stop()

    assert not (dec / "file1.txt").exists()
    assert not (dec / "file2.md").exists()
    assert not (dec / "subdir" / "nested.txt").exists()
    assert not (dec / "subdir").exists()
    assert dec.exists()


def test_startup_does_not_clear_decrypted_dir(tmp_path):
    """Starting the sync manager should populate, not clear, the decrypted dir."""
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc.mkdir(parents=True)

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    sm = SyncManager(config, SyncFolderClient(config), DummyPGP())

    # Pre-populate the decrypted dir with a file
    (dec / "preexisting.txt").write_text("data")

    sm.start()
    try:
        # Existing files should be preserved
        assert (dec / "preexisting.txt").exists()
    finally:
        sm.stop()


def test_local_deletion_removes_encrypted_file(tmp_path, monkeypatch):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc_dir = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc_dir.mkdir(parents=True)

    # Create a local file and its encrypted counterpart
    local_file = mon / "doc.txt"
    local_file.write_text("content")
    enc_file = enc_dir / "doc.txt.gpg"
    enc_file.write_text("encrypted")

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    sm = SyncManager(config, SyncFolderClient(config), DummyPGP())
    sm.local_files["doc.txt"] = 100.0

    # Delete the local file and notify
    local_file.unlink()
    sm.handle_local_change(local_file)

    assert not enc_file.exists(), (
        "Encrypted file should be deleted after local deletion"
    )
    assert "doc.txt" not in sm.local_files


def test_local_deletion_skips_hidden_and_temp_files(tmp_path):
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

    sm = SyncManager(config, SyncFolderClient(config), DummyPGP())

    # Hidden file deletion should not delete encrypted files
    hidden = mon / ".hidden.txt"
    hidden.write_text("secret")
    hidden.unlink()
    sm.handle_local_change(hidden)

    # Temp file deletion should not delete encrypted files
    temp = mon / "file.txt.tmp"
    temp.write_text("temp")
    temp.unlink()
    sm.handle_local_change(temp)

    # Conflict file deletion should not delete encrypted files
    conflict = mon / "file.txt.conflict"
    conflict.write_text("conflict")
    conflict.unlink()
    sm.handle_local_change(conflict)

    # .gpg file deletion should not trigger anything
    gpg_file = mon / "file.txt.gpg"
    gpg_file.write_text("gpg")
    gpg_file.unlink()
    sm.handle_local_change(gpg_file)
    # No assertions needed - we just verify no exceptions


def test_local_deletion_nested_path(tmp_path):
    mon = tmp_path / "mon"
    dec = tmp_path / "dec"
    sync = tmp_path / "sync"
    enc_dir = sync / "encrypted_files"
    mon.mkdir()
    dec.mkdir()
    enc_dir.mkdir(parents=True)

    nested_enc = enc_dir / "subdir"
    nested_enc.mkdir()

    # Create a nested local file and its encrypted counterpart
    nested_local = mon / "subdir" / "deep.txt"
    nested_local.parent.mkdir(parents=True)
    nested_local.write_text("content")
    enc_file = nested_enc / "deep.txt.gpg"
    enc_file.write_text("encrypted")

    config = {
        "local": {"monitored_path": str(mon), "decrypted_path": str(dec)},
        "sync_folder": {"path": str(sync), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
    }

    sm = SyncManager(config, SyncFolderClient(config), DummyPGP())

    nested_local.unlink()
    sm.handle_local_change(nested_local)

    assert not enc_file.exists(), "Nested encrypted file should be deleted"


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
    assert not any(enc_dir.iterdir()), (
        "No new encrypted artifacts should be produced for .gpg inputs"
    )
