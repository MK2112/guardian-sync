import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
import pytest
import shutil
from src.sync_folder_client import SyncFolderClient


def test_detect_sync_folder_path(monkeypatch, tmp_path):
    # Simulate folder detection
    folder = tmp_path / "OneDrive"
    folder.mkdir()
    config = {
        "sync_folder": {"path": str(folder), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    assert os.path.exists(client.sync_folder_path)


def test_upload_and_list_files(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    test_file = tmp_path / "foo.txt"
    test_file.write_text("bar")
    _ = client.upload_file(str(test_file))
    files = client.list_files()
    assert any(f["name"] == "foo.txt" for f in files)


def test_download_file(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    src = tmp_path / "foo.txt"
    src.write_text("bar")
    client.upload_file(str(src))
    out = tmp_path / "out.txt"
    client.download_file("foo.txt", str(out))
    assert out.read_text() == "bar"


def test_download_nonexistent_file(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    with pytest.raises(FileNotFoundError):
        client.download_file("doesnotexist.txt", str(tmp_path / "out.txt"))


def test_upload_overwrites(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    test_file = tmp_path / "foo.txt"
    test_file.write_text("bar")
    client.upload_file(str(test_file))
    # Overwrite
    test_file.write_text("baz")
    client.upload_file(str(test_file))
    files = client.list_files()
    assert any(f["name"] == "foo.txt" for f in files)


def test_ensure_folder_exists_nested(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    folder = "nested/folder/structure"
    _ = client.ensure_folder_exists(folder)
    assert os.path.exists(os.path.join(tmp_path, folder))


def test_ensure_folder_exists(tmp_path):
    config = {
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"}
    }
    client = SyncFolderClient(config)
    folder = "custom_folder"
    _ = client.ensure_folder_exists(folder)
    assert os.path.exists(os.path.join(tmp_path, folder))
