import os
import struct
import logging

from typing import Tuple, Optional

try:
    import oqs as liboqs
except ImportError:
    liboqs = None


class HybridEncryptionUnavailableError(Exception):
    # Raised when post-quantum encryption is requested but unavailable.
    pass


class HybridEncryption:
    # Hybrid encryption using ML-KEM for key exchange and ChaCha20-Poly1305 for symmetric encryption.
    # [Version: 1 byte][KEM pubkey: ~1184 bytes][Ciphertext: variable][AuthTag: 16 bytes]
    # File format version for hybrid encryption
    HYBRID_FORMAT_VERSION = 1

    # ML-KEM variant (post-quantum key encapsulation)
    KEM_ALGORITHM = "ML-KEM-768"  # 768-bit security level

    # ChaCha20-Poly1305 for symmetric encryption
    NONCE_SIZE = 12  # bytes
    AUTH_TAG_SIZE = 16  # bytes
    KEY_SIZE = 32  # bytes for ChaCha20

    def __init__(self):
        if liboqs is None:
            raise HybridEncryptionUnavailableError(
                "liboqs not installed. Install with: pip install liboqs-python"
            )
        self.logger = logging.getLogger(__name__)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        # Generate post-quantum keypair using ML-KEM
        # Tuple of (public_key, secret_key) bytes
        try:
            kem = liboqs.KeyEncapsulation(self.KEM_ALGORITHM)
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            self.logger.info(f"Generated {self.KEM_ALGORITHM} keypair")
            return public_key, secret_key
        except Exception as e:
            raise RuntimeError(f"Keypair generation failed: {str(e)}")

    def encrypt_hybrid(self, plaintext: bytes, public_key: bytes) -> bytes:
        # Encrypt plaintext using hybrid encryption.
        # Returns encrypted blob in format: [version][kem_ciphertext][nonce][ciphertext][auth_tag]
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            # KEM encapsulation to get symmetric key
            kem = liboqs.KeyEncapsulation(self.KEM_ALGORITHM)
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # Derive symmetric key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=None,
                info=b"hybrid-encryption",
            )
            symmetric_key = hkdf.derive(shared_secret)

            # Generate random nonce
            nonce = os.urandom(self.NONCE_SIZE)

            # Encrypt with ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(symmetric_key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Build output: version + kem_ciphertext + nonce + ciphertext
            output = struct.pack("B", self.HYBRID_FORMAT_VERSION)
            output += kem_ciphertext
            output += nonce
            output += ciphertext  # includes auth tag

            self.logger.debug(f"Encrypted {len(plaintext)} bytes (hybrid)")
            return output

        except ImportError as e:
            raise HybridEncryptionUnavailableError(
                f"Required cryptography library not available: {str(e)}"
            )
        except Exception as e:
            raise RuntimeError(f"Hybrid encryption failed: {str(e)}")

    def decrypt_hybrid(self, encrypted_blob: bytes, secret_key: bytes) -> bytes:
        # Decrypt data encrypted with encrypt_hybrid.
        # Returns decrypted plaintext
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            if len(encrypted_blob) < 1:
                raise ValueError("Encrypted blob too short")

            version = struct.unpack("B", encrypted_blob[0:1])[0]
            if version != self.HYBRID_FORMAT_VERSION:
                raise ValueError(f"Unsupported format version: {version}")

            offset = 1

            # ML-KEM public key size (for ML-KEM-768)
            kem_ciphertext_size = 1088  # Fixed size for ML-KEM-768
            if (
                len(encrypted_blob)
                < offset + kem_ciphertext_size + self.NONCE_SIZE + self.AUTH_TAG_SIZE
            ):
                raise ValueError("Encrypted blob malformed or corrupted")

            kem_ciphertext = encrypted_blob[offset : offset + kem_ciphertext_size]
            offset += kem_ciphertext_size

            nonce = encrypted_blob[offset : offset + self.NONCE_SIZE]
            offset += self.NONCE_SIZE

            ciphertext_and_tag = encrypted_blob[offset:]

            # KEM decapsulation to recover symmetric key
            kem = liboqs.KeyEncapsulation(self.KEM_ALGORITHM, secret_key)
            shared_secret = kem.decap_secret(kem_ciphertext)

            # Derive symmetric key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=None,
                info=b"hybrid-encryption",
            )
            symmetric_key = hkdf.derive(shared_secret)

            # Decrypt with ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(symmetric_key)
            plaintext = cipher.decrypt(nonce, ciphertext_and_tag, None)

            self.logger.debug(f"Decrypted {len(plaintext)} bytes (hybrid)")
            return plaintext

        except ImportError as e:
            raise HybridEncryptionUnavailableError(
                f"Required cryptography library not available: {str(e)}"
            )
        except Exception as e:
            raise RuntimeError(f"Hybrid decryption failed: {str(e)}")

    def is_hybrid_encrypted(self, data: bytes) -> bool:
        # Check if data appears to be hybrid-encrypted (has version marker)
        if len(data) < 1:
            return False
        version = struct.unpack("B", data[0:1])[0]
        return version == self.HYBRID_FORMAT_VERSION
