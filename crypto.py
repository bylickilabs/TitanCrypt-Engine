import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

@dataclass
class KdfParams:
    iterations: int
    salt: bytes

def derive_key(password: str, params: KdfParams, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=length,
        salt=params.salt,
        iterations=params.iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

def generate_salt(size: int = 16) -> bytes:
    return os.urandom(size)

def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)