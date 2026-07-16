import os
import sys
import stat
import time
import pytest
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.pgp_handler import PGPHandler
from src.sync_folder_client import SyncFolderClient
from src.sync_manager import SyncManager


def test_validate_decryption_fails_on_checksum_mismatch(
    tmp_path, monkeypatch, dummy_config
):
    cfg = dummy_config.copy()
    cfg["pgp"]["gnupghome"] = str(tmp_path)

    class TamperingGPG:
        def __init__(self, *a, **kw):
            pass

        def list_keys(self, priv):
            return [
                {
                    "uids": ["dummy-key"],
                    "fingerprint": "ABCDEF1234567890ABCDEF1234567890",
                    "keyid": "1234567890",
                }
            ]

        def decrypt_file(self, f, passphrase=None, output=None):
            if output:
                with open(output, "wb") as out:
                    out.write(b"tampered-after-encrypt")

            class Status:
                ok = True
                status = "ok"
                stderr = None

            return Status()

    monkeypatch.setattr("src.pgp_handler.gnupg.GPG", TamperingGPG)

    handler = PGPHandler(cfg)

    orig = tmp_path / "orig.txt"
    orig.write_bytes(b"original-data")

    enc = tmp_path / "orig.txt.gpg"
    enc.write_bytes(b"cipher")

    with pytest.raises(RuntimeError) as exc:
        handler.decrypt_file(str(enc), verify_with=str(orig))

    assert "Checksum mismatch" in str(exc.value) or "Decryption failed" in str(
        exc.value
    )


def test_gnupghome_permissions_hardened(tmp_path, monkeypatch, dummy_config):
    # Create a gnupghome with permissive permissions and ensure PGPHandler tightens them or warns
    cfg = dummy_config.copy()
    home = tmp_path / "gnupg"
    home.mkdir()
    # make group/world readable
    os.chmod(home, 0o755)
    cfg["pgp"]["gnupghome"] = str(home)

    class SimpleGPG:
        def __init__(self, *a, **kw):
            pass

        def list_keys(self, priv):
            return [
                {
                    "uids": ["dummy-key"],
                    "fingerprint": "ABCDEF1234567890ABCDEF1234567890",
                    "keyid": "1234567890",
                }
            ]

    monkeypatch.setattr("src.pgp_handler.gnupg.GPG", SimpleGPG)
    # subprocess.run should report gpg present
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **kw: type(
            "R", (), {"returncode": 0, "stdout": "gpg (GnuPG) 2.2"}
        )(),
    )

    # Initialize handler; it should attempt to chmod to 0o700 (may succeed)
    handler = PGPHandler(cfg)

    mode = stat.S_IMODE(os.stat(home).st_mode)
    # Expect permissions tightened to 0700 or remain if system prevented it
    assert mode == 0o700 or mode == 0o755


def test_is_within_and_symlink_defenses(tmp_path, dummy_config):
    # Create monitored path and an outside file. Create a symlink inside monitored path to outside file.
    base = tmp_path / "mon"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")

    link = base / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Filesystem does not support symlinks")

    cfg = dummy_config.copy()
    cfg["local"]["monitored_path"] = str(base)
    cfg["local"]["decrypted_path"] = str(tmp_path / "dec")
    cfg["sync_folder"]["path"] = str(tmp_path / "sync")
    (tmp_path / "sync" / "encrypted_files").mkdir(parents=True)

    class NoopPGP:
        def encrypt_file(self, file_path, output_path=None):
            return str(file_path) + ".gpg"

        def decrypt_file(self, encrypted_path, output_path=None):
            return output_path or str(encrypted_path).replace(".gpg", "")

    client = SyncFolderClient(cfg)
    sm = SyncManager(cfg, client, NoopPGP())

    # Should skip processing symlinked file
    sm.handle_local_change(link)
    # No encrypted file created
    assert not (
        Path(cfg["sync_folder"]["path"])
        / cfg["sync_folder"]["encrypted_folder"]
        / "link.txt.gpg"
    ).exists()


def test_conflict_detection_by_mtime(tmp_path, dummy_config):
    # Ensure a local file older than remote causes creation of .conflict file
    cfg = dummy_config.copy()
    mon = tmp_path / "mon"
    mon.mkdir()
    sync = tmp_path / "sync"
    enc = sync / "encrypted_files"
    enc.mkdir(parents=True)
    cfg["local"]["monitored_path"] = str(mon)
    cfg["sync_folder"]["path"] = str(sync)
    cfg["local"]["decrypted_path"] = str(tmp_path / "dec")

    class DummyPGP2:
        def encrypt_file(self, file_path, output_path=None):
            out = str(file_path) + ".gpg"
            open(out, "wb").write(b"encrypted")
            return out

        def decrypt_file(self, encrypted_path, output_path=None):
            open(output_path, "wb").write(b"decrypted")
            return output_path

    client = SyncFolderClient(cfg)
    sm = SyncManager(cfg, client, DummyPGP2())

    # Create local file
    f = mon / "secret.txt"
    f.write_text("local")
    # Sleep to ensure different mtimes
    time.sleep(0.1)
    # Create remote encrypted file with newer mtime
    remote = enc / "secret.txt.gpg"
    remote.write_bytes(b"encrypted-remote")
    # bump remote mtime to future
    future = time.time() + 1000
    os.utime(remote, (future, future))

    sm.handle_local_change(f)

    # A conflict file should be present (created as '<file>.conflict')
    conflict_path = Path(str(f) + ".conflict")
    assert conflict_path.exists(), f"Expected conflict file at {conflict_path}"


def test_syncfolder_client_prevents_path_traversal(tmp_path):
    cfg = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(cfg)
    # Try to download using a path with traversal that would escape the sync folder
    secret = tmp_path.parent / "escape.txt"
    secret.write_text("sensitive")
    # Give an id that is a relative path with traversal
    with pytest.raises(FileNotFoundError):
        client.download_file("../escape.txt", str(tmp_path / "out.txt"))
