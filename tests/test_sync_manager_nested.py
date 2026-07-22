import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from src.sync_manager import SyncManager
from src.sync_folder_client import SyncFolderClient


class WritingDummyPGP:
    def encrypt_file(self, file_path, output_path=None):
        out = output_path or (str(file_path) + ".gpg")
        with open(out, "w") as f:
            f.write("encrypted")
        return out

    def decrypt_file(self, encrypted_path, output_path=None):
        out = output_path or str(encrypted_path).replace(".gpg", "")
        with open(out, "w") as f:
            f.write("decrypted")
        return out


def test_handle_local_change_nested_paths(tmp_path):
    # Arrange config with nested paths
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
    sm = SyncManager(config, client, WritingDummyPGP())

    # Create nested file
    nested_dir = mon / "sub1" / "sub2"
    nested_dir.mkdir(parents=True)
    f = nested_dir / "secret.txt"
    f.write_text("plain")

    # Act
    sm.handle_local_change(f)

    # Assert upload path respects nested structure
    expected_enc = enc_dir / "sub1" / "sub2" / "secret.txt.gpg"
    assert expected_enc.exists(), f"Expected encrypted file at {expected_enc}"

    # Now simulate a remote change notification and ensure decryption preserves nested structure
    sm.handle_sync_folder_change(expected_enc)
    expected_dec = dec / "sub1" / "sub2" / "secret.txt"
    assert expected_dec.exists(), "Decrypted file should preserve nested structure"
