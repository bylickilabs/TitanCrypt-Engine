import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple

from cryptography.exceptions import InvalidTag

from .crypto import (
    KdfParams,
    derive_key,
    generate_salt,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from .fsutil import collect_entries, FileEntry

MAGIC = b"SECARC01"
VERSION = 1
PAYLOAD_SEPARATOR = b"\n---PAYLOAD---\n"

class SecureArchiveError(Exception):
    """Base exception for all SecureArchive-related errors."""
    pass

class InvalidContainerError(SecureArchiveError):
    """Raised when the container is corrupted, invalid or unreadable."""
    pass

class WrongPasswordError(SecureArchiveError):
    """Raised when AES-GCM decryption fails due to an incorrect password."""
    pass

@dataclass
class ContainerHeader:
    version: int
    salt: bytes
    iterations: int
    nonce: bytes


def _build_header_bytes(header: ContainerHeader) -> bytes:
    salt_len = len(header.salt)
    nonce_len = len(header.nonce)
    data = bytearray()
    data.extend(MAGIC)
    data.append(header.version & 0xFF)
    data.append(salt_len & 0xFF)
    data.extend(header.salt)
    data.extend(header.iterations.to_bytes(4, "big"))
    data.append(nonce_len & 0xFF)
    data.extend(header.nonce)
    return bytes(data)


def _parse_header_bytes(data: bytes) -> Tuple[ContainerHeader, bytes]:
    if len(data) < 8 + 1 + 1 + 4 + 1:
        raise InvalidContainerError("Header too short")

    offset = 0
    magic = data[offset:offset + 8]
    offset += 8
    if magic != MAGIC:
        raise InvalidContainerError("Magic mismatch")

    version = data[offset]
    offset += 1
    if version != VERSION:
        raise InvalidContainerError("Unsupported version")

    salt_len = data[offset]
    offset += 1
    if len(data) < offset + salt_len + 4 + 1:
        raise InvalidContainerError("Header corrupt")
    salt = data[offset:offset + salt_len]
    offset += salt_len

    iterations = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4

    nonce_len = data[offset]
    offset += 1

    if len(data) < offset + nonce_len:
        raise InvalidContainerError("Header corrupt (nonce)")
    nonce = data[offset:offset + nonce_len]
    offset += nonce_len

    header = ContainerHeader(
        version=version,
        salt=salt,
        iterations=iterations,
        nonce=nonce,
    )
    remaining = data[offset:]
    return header, remaining


def encrypt_path(
    input_path: str,
    container_path: str,
    password: str,
    iterations: int = 300_000,
    overwrite: bool = False,
) -> None:
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(input_path)

    dst = Path(container_path)
    if dst.exists() and not overwrite:
        raise FileExistsError(container_path)

    entries: List[FileEntry] = collect_entries(src)
    if not entries:
        raise SecureArchiveError("Input path contains no files.")

    salt = generate_salt(16)
    kdf_params = KdfParams(iterations=iterations, salt=salt)
    key = derive_key(password, kdf_params)

    manifest: Dict[str, Any] = {
        "version": VERSION,
        "cipher": "AES-256-GCM",
        "kdf": {
            "type": "PBKDF2-SHA512",
            "iterations": iterations,
            "salt_hex": salt.hex(),
        },
        "root": str(src.resolve()),
        "entries": [],
    }

    data_chunks = bytearray()
    current_offset = 0

    for e in entries:
        with open(e.abs_path, "rb") as f:
            content = f.read()
        start = current_offset
        data_chunks.extend(content)
        length = len(content)
        current_offset += length

        manifest["entries"].append(
            {
                "path": e.rel_path,
                "size": e.size,
                "mtime": e.mtime,
                "offset": start,
                "length": length,
            }
        )

    manifest_bytes = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    payload = manifest_bytes + PAYLOAD_SEPARATOR + bytes(data_chunks)

    nonce, ciphertext = encrypt_aes_gcm(key, payload, aad=MAGIC)

    header = ContainerHeader(
        version=VERSION,
        salt=salt,
        iterations=iterations,
        nonce=nonce,
    )
    header_bytes = _build_header_bytes(header)

    with open(dst, "wb") as out:
        out.write(header_bytes)
        out.write(ciphertext)


def _load_and_decrypt(container_path: str, password: str) -> Tuple[Dict[str, Any], bytes, ContainerHeader]:
    p = Path(container_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(container_path)

    with open(p, "rb") as f:
        file_data = f.read()

    header, ciphertext = _parse_header_bytes(file_data)

    kdf_params = KdfParams(iterations=header.iterations, salt=header.salt)
    key = derive_key(password, kdf_params)

    try:
        plaintext = decrypt_aes_gcm(key, header.nonce, ciphertext, aad=MAGIC)
    except InvalidTag as ex:
        raise WrongPasswordError("Decryption failed") from ex

    try:
        manifest_part, data_part = plaintext.split(PAYLOAD_SEPARATOR, 1)
    except ValueError as ex:
        raise InvalidContainerError("Payload separator missing") from ex

    try:
        manifest = json.loads(manifest_part.decode("utf-8"))
    except json.JSONDecodeError as ex:
        raise InvalidContainerError("Manifest JSON invalid") from ex

    return manifest, data_part, header


def decrypt_container(container_path: str, output_path: str, password: str) -> None:
    manifest, data_part, _header = _load_and_decrypt(container_path, password)

    out_root = Path(output_path)
    out_root.mkdir(parents=True, exist_ok=True)

    for entry in manifest.get("entries", []):
        rel_path = entry["path"]
        offset = entry["offset"]
        length = entry["length"]
        chunk = data_part[offset:offset + length]

        target_path = out_root / rel_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "wb") as f:
            f.write(chunk)


def list_container(container_path: str, password: str) -> List[Dict[str, Any]]:
    manifest, _data_part, _header = _load_and_decrypt(container_path, password)
    return manifest.get("entries", [])


def verify_container(container_path: str, password: str) -> bool:
    try:
        manifest, data_part, _header = _load_and_decrypt(container_path, password)
    except WrongPasswordError:
        return False
    except SecureArchiveError:
        return False

    entries = manifest.get("entries", [])
    max_offset = 0
    for e in entries:
        offset = e["offset"]
        length = e["length"]
        if offset < 0 or length < 0:
            return False
        end = offset + length
        if end > max_offset:
            max_offset = end

    if max_offset > len(data_part):
        return False

    return True


def change_password(
    container_path: str,
    old_password: str,
    new_password: str,
    iterations: int | None = None,
) -> None:
    manifest, data_part, old_header = _load_and_decrypt(container_path, old_password)

    if iterations is None:
        iterations = old_header.iterations

    new_salt = generate_salt(16)
    kdf_params = KdfParams(iterations=iterations, salt=new_salt)
    key = derive_key(new_password, kdf_params)

    manifest["kdf"] = {
        "type": "PBKDF2-SHA512",
        "iterations": iterations,
        "salt_hex": new_salt.hex(),
    }

    manifest_bytes = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    payload = manifest_bytes + PAYLOAD_SEPARATOR + data_part

    nonce, ciphertext = encrypt_aes_gcm(key, payload, aad=MAGIC)

    new_header = ContainerHeader(
        version=VERSION,
        salt=new_salt,
        iterations=iterations,
        nonce=nonce,
    )
    header_bytes = _build_header_bytes(new_header)

    p = Path(container_path)
    with open(p, "wb") as out:
        out.write(header_bytes)
        out.write(ciphertext)