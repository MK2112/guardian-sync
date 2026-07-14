import os
import sys
import pytest
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from src.pgp_handler import PGPHandler


# Dummy GPG that simulates success
class DummyGPG:
    def __init__(self, *a, **kw):
        self.encrypt_file_called = False
        self.decrypt_file_called = False
        self.list_keys = lambda priv: [{"uids": ["dummy-key"]}]

    def encrypt_file(self, f, recipients, output, always_trust):
        self.encrypt_file_called = True

        class Status:
            ok = True
            status = "encryption ok"
            stderr = None

        return Status()

    def decrypt_file(self, f, passphrase, output):
        self.decrypt_file_called = True

        class Status:
            ok = True
            status = "decryption ok"
            stderr = None

        return Status()


@mock.patch("src.pgp_handler.gnupg.GPG", new=DummyGPG)
def test_encrypt_file_success(dummy_config, tmp_path):
    handler = PGPHandler(dummy_config)
    test_file = tmp_path / "test.txt"
    test_file.write_text("secret")
    out = handler.encrypt_file(str(test_file))
    assert out.endswith(".gpg")
    assert handler.gpg.encrypt_file_called


@mock.patch("src.pgp_handler.gnupg.GPG", new=DummyGPG)
def test_decrypt_file_success(dummy_config, tmp_path):
    handler = PGPHandler(dummy_config)
    enc_file = tmp_path / "secret.txt.gpg"
    enc_file.write_bytes(b"dummy")
    out = handler.decrypt_file(str(enc_file))
    assert str(out).endswith("secret.txt")
    assert handler.gpg.decrypt_file_called


def test_missing_key_raises(dummy_config):
    class NoKeyGPG:
        def __init__(self, *a, **kw):
            pass

        def list_keys(self, priv):
            return []

    with mock.patch("src.pgp_handler.gnupg.GPG", new=NoKeyGPG):
        with mock.patch("subprocess.run") as m:
            m.return_value.returncode = 0
            m.return_value.stdout = "gpg (GnuPG) 2.2.0\n"
            with pytest.raises(RuntimeError, match="PGP key 'dummy-key' not found"):
                PGPHandler(dummy_config)


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_encrypt_invalid_file(MockGPG, dummy_config, tmp_path):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    handler = PGPHandler(dummy_config)
    with pytest.raises(RuntimeError, match="Encryption failed: I/O or GPG error"):
        handler.encrypt_file(str(tmp_path / "doesnotexist.txt"))


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_decrypt_invalid_file(MockGPG, dummy_config, tmp_path):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    handler = PGPHandler(dummy_config)
    with pytest.raises(RuntimeError, match="Decryption failed after"):
        handler.decrypt_file(str(tmp_path / "doesnotexist.txt.gpg"))


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_missing_passphrase_prompts(MockGPG, dummy_config, tmp_path, monkeypatch):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    MockGPG.return_value.encrypt_file.return_value.ok = True
    MockGPG.return_value.encrypt_file.return_value.status = "encryption ok"
    MockGPG.return_value.encrypt_file.return_value.stderr = None

    handler = PGPHandler(dummy_config)
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello")

    # Simulate interactive passphrase entry
    monkeypatch.setattr("getpass.getpass", lambda prompt: "injected-pass")
    handler.passphrase = None

    out_file = handler.encrypt_file(str(test_file))

    # Simulate encryption result file creation
    Path(out_file).write_text("fake encrypted data")

    assert os.path.exists(out_file)


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_decrypt_fails_then_cleans_up(MockGPG, dummy_config, tmp_path, monkeypatch):
    test_file = tmp_path / "bad.gpg"
    test_file.write_bytes(b"bad-data")
    output_file = str(test_file).replace(".gpg", "")

    # Simulate 3 failed decryption attempts
    class FailingGPG:
        def __init__(self, *a, **kw):
            pass

        def list_keys(self, priv):
            return [{"uids": ["dummy-key"]}]

        def decrypt_file(self, f, passphrase, output):
            class Status:
                ok = False
                status = "decryption failed"
                stderr = "Bad passphrase"

            return Status()

    MockGPG.return_value = FailingGPG()

    # Simulate wrong input all 3 times
    monkeypatch.setattr("getpass.getpass", lambda prompt: "wrong-pass")

    with pytest.raises(RuntimeError, match="Decryption failed after 3 attempts"):
        handler = PGPHandler(dummy_config)
        handler.passphrase = None
        handler.decrypt_file(str(test_file), output_file)

    assert not os.path.exists(output_file), "Partial decrypted file was not cleaned up"


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_decrypt_overwrites_existing_output(
    MockGPG, dummy_config, tmp_path, monkeypatch
):
    # Simulate GPG with required methods
    class SuccessGPG:
        def list_keys(self, priv):
            return [{"uids": ["dummy-key"]}]

        def decrypt_file(self, f, passphrase, output):
            with open(output, "wb") as out_f:
                out_f.write(b"decrypted content")

            class Status:
                ok = True
                status = "ok"
                stderr = None

            return Status()

    MockGPG.return_value = SuccessGPG()

    enc_file = tmp_path / "conflict.txt.gpg"
    enc_file.write_bytes(b"ciphertext")

    output_file = tmp_path / "conflict.txt"
    output_file.write_text("old content")

    monkeypatch.setattr("getpass.getpass", lambda prompt: "pass")

    handler = PGPHandler(dummy_config)
    handler.passphrase = None
    result_path = handler.decrypt_file(str(enc_file))

    with open(result_path, "rb") as f:
        data = f.read()

    assert data == b"decrypted content", "File should be overwritten"


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_encrypt_empty_file(MockGPG, dummy_config, tmp_path):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    MockGPG.return_value.encrypt_file.return_value.ok = True
    MockGPG.return_value.encrypt_file.return_value.status = "ok"
    MockGPG.return_value.encrypt_file.return_value.stderr = None

    handler = PGPHandler(dummy_config)

    empty_file = tmp_path / "empty.txt"
    empty_file.touch()

    encrypted = handler.encrypt_file(str(empty_file))
    assert encrypted.endswith(".gpg")


def test_gpg_binary_missing(dummy_config):
    with mock.patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(EnvironmentError, match="GnuPG binary not found"):
            PGPHandler(dummy_config)


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_passphrase_falls_back_to_env_var(MockGPG, dummy_config, monkeypatch):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    config_no_pass = dict(dummy_config)
    config_no_pass["pgp"] = dict(dummy_config["pgp"])
    config_no_pass["pgp"]["passphrase"] = ""

    monkeypatch.setenv("GUARDIAN_SYNC_PASSPHRASE", "env-passphrase")

    handler = PGPHandler(config_no_pass)
    assert handler.passphrase == "env-passphrase"


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_config_passphrase_takes_precedence_over_env_var(
    MockGPG, dummy_config, monkeypatch
):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    monkeypatch.setenv("GUARDIAN_SYNC_PASSPHRASE", "env-passphrase")

    handler = PGPHandler(dummy_config)
    assert handler.passphrase == "dummy-passphrase"


@mock.patch("src.pgp_handler.gnupg.GPG")
def test_no_passphrase_no_env_var_leaves_none(MockGPG, dummy_config):
    MockGPG.return_value.list_keys.return_value = [{"uids": ["dummy-key"]}]
    config_no_pass = dict(dummy_config)
    config_no_pass["pgp"] = dict(dummy_config["pgp"])
    config_no_pass["pgp"]["passphrase"] = ""

    with mock.patch.dict(os.environ, clear=True):
        handler = PGPHandler(config_no_pass)
        assert handler.passphrase is None

    # Cleanup: restore env in case other tests rely on it
    if "GUARDIAN_SYNC_PASSPHRASE" in os.environ:
        del os.environ["GUARDIAN_SYNC_PASSPHRASE"]
