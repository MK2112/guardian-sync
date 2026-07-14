import os
import gnupg
import logging
import subprocess
import getpass
import shutil
import tempfile
import hashlib


def _zero(buf):
    if buf is None:
        return
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


class PGPHandler:
    MAX_PASSPHRASE_RETRIES = 3

    def __init__(self, config):
        self.config = config
        try:
            result = subprocess.run(
                ["gpg", "--version"], capture_output=True, text=True
            )
            if result.returncode != 0:
                raise EnvironmentError("GnuPG is installed but returned an error.")
            logging.info(f"Using GnuPG: {result.stdout.splitlines()[0]}")
        except FileNotFoundError:
            raise EnvironmentError(
                "GnuPG binary not found. Please install it and ensure it's on the PATH."
            )

        gnupg_home = os.path.expanduser(config["pgp"]["gnupghome"])
        os.makedirs(gnupg_home, exist_ok=True)
        try:
            st = os.stat(gnupg_home)
            if (st.st_mode & 0o077) != 0:
                try:
                    os.chmod(gnupg_home, 0o700)
                    logging.warning(
                        f"Adjusted permissions on GnuPG home to 0700: {gnupg_home}"
                    )
                except Exception as e:
                    logging.warning(
                        f"GnuPG home has permissive permissions and could not be fixed automatically: {gnupg_home} ({e})"
                    )
        except FileNotFoundError:
            pass

        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        self.key_name = config["pgp"]["key_name"]
        config_pass = config["pgp"].get("passphrase")
        self._passphrase = None
        if config_pass:
            self._passphrase = bytearray(config_pass, "utf-8")
        elif os.environ.get("GUARDIAN_SYNC_PASSPHRASE"):
            self._passphrase = bytearray(
                os.environ["GUARDIAN_SYNC_PASSPHRASE"], "utf-8"
            )
            os.environ.pop("GUARDIAN_SYNC_PASSPHRASE", None)
        self.always_trust = bool(config["pgp"].get("always_trust", False))
        self._verify_key()

    @property
    def passphrase(self):
        return self._passphrase.decode("utf-8") if self._passphrase else None

    @passphrase.setter
    def passphrase(self, value):
        _zero(self._passphrase)
        self._passphrase = bytearray(value, "utf-8") if value else None

    def _verify_key(self):
        try:
            keys = self.gpg.list_keys(True)
            key_exists = any(
                self.key_name in key["uids"][0] for key in keys if "uids" in key
            )
            if not key_exists:
                raise ValueError(
                    f"PGP key '{self.key_name}' not found in keyring. Use 'gpg --import' or generate it with 'gpg --full-generate-key'."
                )
        except Exception as e:
            raise RuntimeError(f"Failed to access GPG keyring: {str(e)}")

    def encrypt_file(self, file_path, output_path=None):
        if output_path is None:
            output_path = str(file_path) + ".gpg"

        try:
            with open(file_path, "rb") as f:
                status = self.gpg.encrypt_file(
                    f,
                    recipients=[self.key_name],
                    output=output_path,
                    always_trust=self.always_trust,
                )
        except Exception as e:
            raise RuntimeError(f"Encryption failed: I/O or GPG error: {str(e)}")

        if status.ok:
            logging.info(f"Encrypted {file_path} to {output_path}")
            return output_path
        else:
            self._remove(output_path)
            raise RuntimeError(f"Encryption failed: {status.status} — {status.stderr}")

    def decrypt_file(self, encrypted_path, output_path=None, verify_with=None):
        if output_path is None:
            output_path = str(encrypted_path)
            if output_path.endswith(".gpg"):
                output_path = output_path[:-4]

        last_error = None
        for attempt in range(1, self.MAX_PASSPHRASE_RETRIES + 1):
            temp_fd, temp_path = tempfile.mkstemp()
            os.close(temp_fd)

            secret = None
            try:
                raw = self.passphrase or getpass.getpass(
                    f"Enter PGP passphrase (attempt {attempt}/{self.MAX_PASSPHRASE_RETRIES}): "
                )

                secret = bytearray(raw, "utf-8")

                with open(encrypted_path, "rb") as f:
                    status = self.gpg.decrypt_file(
                        f, passphrase=secret.decode("utf-8"), output=temp_path
                    )

                if status.ok:
                    if verify_with:
                        if not self._validate_decryption(verify_with, temp_path):
                            raise ValueError(
                                "Checksum mismatch: decrypted file does not match original."
                            )
                    shutil.move(temp_path, output_path)
                    logging.info(f"Decrypted {encrypted_path} to {output_path}")
                    return output_path
                else:
                    logging.warning(
                        f"Attempt {attempt}: Decryption failed — {status.status}"
                    )
                    last_error = RuntimeError(
                        f"Decryption failed: {status.status} — {status.stderr}"
                    )
            except Exception as e:
                logging.error(
                    f"Attempt {attempt}: Decryption raised an error: {str(e)}"
                )
                last_error = e
            finally:
                _zero(secret)
                self._remove(temp_path)

        raise RuntimeError(
            f"Decryption failed after {self.MAX_PASSPHRASE_RETRIES} attempts. Last error: {last_error}"
        )

    def clear_passphrase(self):
        _zero(self._passphrase)
        self._passphrase = None

    def _remove(self, path):
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            logging.warning(f"Failed to clean up {path}: {str(e)}")

    def _calculate_checksum(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _validate_decryption(self, original_path, decrypted_path):
        orig_checksum = self._calculate_checksum(original_path)
        dec_checksum = self._calculate_checksum(decrypted_path)
        if orig_checksum != dec_checksum:
            logging.warning(
                f"Checksum mismatch: original={orig_checksum}, decrypted={dec_checksum}"
            )
            return False
        return True
