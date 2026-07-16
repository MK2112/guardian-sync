import os
import json
import logging

from pathlib import Path
from typing import Optional, Tuple

try:
    from .pgp_handler import PGPHandler
    from .hybrid_encryption import HybridEncryption, HybridEncryptionUnavailableError
except ImportError:
    from pgp_handler import PGPHandler
    from hybrid_encryption import HybridEncryption, HybridEncryptionUnavailableError


class HybridPGPHandler:
    # Hybrid encryption handler combining PGP with post-quantum ML-KEM.
    # Metadata file for storing PQ keypairs
    PQ_KEYSTORE_FILE = ".pq_keystore.json"

    def __init__(self, pgp_config: dict, hybrid_mode: bool = True):
        self.logger = logging.getLogger(__name__)
        self.pgp_handler = PGPHandler(pgp_config)
        self.hybrid_mode = hybrid_mode
        self.gnupghome = os.path.expanduser(pgp_config["pgp"]["gnupghome"])

        self.hybrid_crypto = None
        self.pq_public_key = None
        self.pq_secret_key = None

        if hybrid_mode:
            self._init_hybrid_encryption()

    def _init_hybrid_encryption(self):
        # Initialize post-quantum encryption and load/generate keypairs
        try:
            self.hybrid_crypto = HybridEncryption()
            self._load_or_generate_pq_keys()
            self.logger.info("Hybrid encryption initialized successfully")
        except (HybridEncryptionUnavailableError, ImportError) as e:
            self.logger.warning(f"Post-quantum encryption not available: {str(e)}")
            self.hybrid_mode = False

    def _load_or_generate_pq_keys(self):
        keystore_path = os.path.join(self.gnupghome, self.PQ_KEYSTORE_FILE)
        if os.path.exists(keystore_path):
            try:
                with open(keystore_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = self.pgp_handler.gpg.decrypt(
                    encrypted_data, passphrase=self.pgp_handler.passphrase
                )
                if not decrypted_data.ok:
                    raise RuntimeError(
                        f"Keystore decryption failed: {decrypted_data.status}"
                    )
                data = json.loads(str(decrypted_data))
                self.pq_public_key = bytes.fromhex(data["public_key"])
                self.pq_secret_key = bytes.fromhex(data["secret_key"])
                self.logger.info("Loaded existing post-quantum keypair")
                return
            except Exception as e:
                self.logger.warning(
                    f"Failed to load PQ keypair: {str(e)}. Generating new one."
                )

        if self.hybrid_crypto:
            try:
                self.pq_public_key, self.pq_secret_key = (
                    self.hybrid_crypto.generate_keypair()
                )
                self._save_pq_keys(keystore_path)
                self.logger.info("Generated new post-quantum keypair")
            except Exception as e:
                self.logger.error(f"Failed to generate PQ keypair: {str(e)}")
                self.hybrid_mode = False

    def _save_pq_keys(self, keystore_path: str):
        try:
            data = {
                "public_key": self.pq_public_key.hex() if self.pq_public_key else None,
                "secret_key": self.pq_secret_key.hex() if self.pq_secret_key else None,
            }

            os.makedirs(os.path.dirname(keystore_path), exist_ok=True)

            plaintext_bytes = json.dumps(data).encode("utf-8")
            encrypted = self.pgp_handler.gpg.encrypt(
                plaintext_bytes,
                self.pgp_handler.key_fingerprint,
                always_trust=self.pgp_handler.always_trust,
            )
            if not encrypted.ok:
                raise RuntimeError(f"Keystore encryption failed: {encrypted.status}")

            temp_path = keystore_path + ".tmp"
            with open(temp_path, "wb") as f:
                f.write(encrypted.data)

            os.chmod(temp_path, 0o600)
            os.replace(temp_path, keystore_path)
            os.chmod(keystore_path, 0o600)

            self.logger.debug(f"Saved PQ keypair to {keystore_path}")
        except Exception as e:
            self.logger.error(f"Failed to save PQ keypair: {str(e)}")
            raise

    def export_pq_public_key(self, output_path: Optional[str] = None) -> str:
        # Export public key in hybrid format (JSON with both PGP and PQ components).
        # Returns JSON string containing the hybrid public key
        if not self.pq_public_key:
            raise RuntimeError("Post-quantum public key not available")

        # Get PGP public key export
        pgp_keys = self.pgp_handler.gpg.list_keys()
        pgp_key_data = None
        for key in pgp_keys:
            if self.pgp_handler.key_name in key.get("uids", [""])[0]:
                pgp_key_data = {
                    "keyid": key["keyid"],
                    "uid": key["uids"][0] if key["uids"] else None,
                    "pubkey": key["pubkey"],
                }
                break

        hybrid_key = {
            "format_version": 1,
            "pgp": pgp_key_data,
            "pq": {
                "algorithm": "ML-KEM-768",
                "public_key": self.pq_public_key.hex(),
            },
        }

        json_str = json.dumps(hybrid_key, indent=2)

        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)
            os.chmod(output_path, 0o644)  # Public key, readable by all
            self.logger.info(f"Exported hybrid public key to {output_path}")

        return json_str

    def encrypt_file(
        self, file_path: str, output_path: Optional[str] = None, use_hybrid: bool = True
    ) -> str:
        # Encrypt file using hybrid mode if available, otherwise PGP only.
        # Returns path to encrypted file
        if not output_path:
            output_path = str(file_path) + ".gpg"

        # Use PGP encryption (required for all modes)
        pgp_encrypted = self.pgp_handler.encrypt_file(file_path, output_path)

        # If hybrid mode is enabled and PQ keys available, apply hybrid layer
        if use_hybrid and self.hybrid_mode and self.pq_public_key:
            try:
                with open(pgp_encrypted, "rb") as f:
                    pgp_ciphertext = f.read()

                # Apply post-quantum layer on top of PGP
                hybrid_ciphertext = self.hybrid_crypto.encrypt_hybrid(
                    pgp_ciphertext, self.pq_public_key
                )

                # Write hybrid encrypted file
                with open(output_path, "wb") as f:
                    f.write(hybrid_ciphertext)

                self.logger.info(
                    f"Encrypted {file_path} to {output_path} (hybrid PGP + ML-KEM)"
                )
                return output_path

            except HybridEncryptionUnavailableError:
                self.logger.warning("Hybrid encryption unavailable; using PGP only")
                self.hybrid_mode = False
                return pgp_encrypted
            except Exception as e:
                self.logger.error(
                    f"Hybrid encryption layer failed: {str(e)}. Using PGP only."
                )
                return pgp_encrypted

        return pgp_encrypted

    def decrypt_file(
        self,
        encrypted_path: str,
        output_path: Optional[str] = None,
        verify_with: Optional[str] = None,
    ) -> str:
        # Decrypt file, automatically detecting format (hybrid or PGP-only).
        # Returns path to decrypted file
        with open(encrypted_path, "rb") as f:
            data = f.read()

        is_hybrid = self.hybrid_crypto and self.hybrid_crypto.is_hybrid_encrypted(data)

        if is_hybrid and self.pq_secret_key:
            try:
                # Decrypt hybrid layer first (PQ encryption)
                pgp_ciphertext = self.hybrid_crypto.decrypt_hybrid(
                    data, self.pq_secret_key
                )
                import tempfile

                temp_fd, temp_path = tempfile.mkstemp(suffix=".gpg")
                os.close(temp_fd)

                with open(temp_path, "wb") as f:
                    f.write(pgp_ciphertext)

                try:
                    result = self.pgp_handler.decrypt_file(
                        temp_path, output_path, verify_with
                    )
                    self.logger.info(
                        f"Decrypted {encrypted_path} (hybrid PGP + ML-KEM)"
                    )
                    return result
                finally:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)

            except Exception as e:
                self.logger.warning(
                    f"Hybrid decryption failed: {str(e)}. Falling back to PGP-only."
                )
        return self.pgp_handler.decrypt_file(encrypted_path, output_path, verify_with)

    def clear_passphrase(self):
        """Clear the PGP passphrase from memory."""
        self.pgp_handler.clear_passphrase()
