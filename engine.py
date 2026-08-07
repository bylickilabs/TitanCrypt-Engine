import argparse
import fnmatch
import getpass
import json
import math
import os
import stat
import tempfile

from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidTag

if __package__:
    from .crypto import (
        KdfParams,
        derive_key,
        generate_salt,
        encrypt_aes_gcm,
        decrypt_aes_gcm,
    )
    from .fsutil import collect_entries, FileEntry
else:
    from crypto import (
        KdfParams,
        derive_key,
        generate_salt,
        encrypt_aes_gcm,
        decrypt_aes_gcm,
    )
    from fsutil import collect_entries, FileEntry


MAGIC = b"SECARC01"
VERSION = 1
PAYLOAD_SEPARATOR = b"\n---PAYLOAD---\n"

DEFAULT_ITERATIONS = 300_000
MIN_KDF_ITERATIONS = 1
MAX_KDF_ITERATIONS = 10_000_000

EXPECTED_SALT_SIZE = 16
EXPECTED_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16

MAX_MANIFEST_SIZE = 64 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 1_000_000
HEADER_READ_SIZE = 256


__all__ = [
    "SecureArchiveError",
    "InvalidContainerError",
    "WrongPasswordError",
    "ContainerHeader",
    "encrypt_path",
    "decrypt_container",
    "list_container",
    "verify_container",
    "change_password",
    "inspect_container_header",
    "get_container_info",
    "verify_container_detailed",
    "read_file",
    "extract_file",
    "find_files",
    "container_stats",
]


class SecureArchiveError(Exception):
    pass


class InvalidContainerError(SecureArchiveError):
    pass


class WrongPasswordError(SecureArchiveError):
    pass


@dataclass
class ContainerHeader:
    version: int
    salt: bytes
    iterations: int
    nonce: bytes


def _validate_password(
    password: str,
    parameter_name: str = "password",
) -> None:
    if not isinstance(password, str):
        raise TypeError(
            f"{parameter_name} must be a string"
        )


def _validate_iterations(
    iterations: int,
) -> None:
    if isinstance(iterations, bool) or not isinstance(
        iterations,
        int,
    ):
        raise TypeError(
            "iterations must be an integer"
        )

    if iterations < MIN_KDF_ITERATIONS:
        raise ValueError(
            "iterations must be greater than zero"
        )

    if iterations > MAX_KDF_ITERATIONS:
        raise ValueError(
            f"iterations must not exceed {MAX_KDF_ITERATIONS:,}"
        )


def _normalize_internal_path(
    relative_path: str,
) -> str:
    if not isinstance(relative_path, str):
        raise InvalidContainerError(
            "Container path must be a string"
        )

    if not relative_path:
        raise InvalidContainerError(
            "Container path must not be empty"
        )

    if "\x00" in relative_path:
        raise InvalidContainerError(
            "Container path contains a NUL byte"
        )

    windows_path = PureWindowsPath(
        relative_path
    )

    if windows_path.is_absolute():
        raise InvalidContainerError(
            f"Absolute container path is not allowed: {relative_path}"
        )

    if windows_path.drive:
        raise InvalidContainerError(
            f"Drive-based container path is not allowed: {relative_path}"
        )

    if windows_path.root:
        raise InvalidContainerError(
            f"Rooted container path is not allowed: {relative_path}"
        )

    normalized = relative_path.replace(
        "\\",
        "/",
    )

    posix_path = PurePosixPath(
        normalized
    )

    if posix_path.is_absolute():
        raise InvalidContainerError(
            f"Absolute container path is not allowed: {relative_path}"
        )

    parts = posix_path.parts

    if not parts:
        raise InvalidContainerError(
            "Invalid empty container path"
        )

    clean_parts: List[str] = []

    for part in parts:
        if part == "..":
            raise InvalidContainerError(
                f"Parent path traversal is not allowed: {relative_path}"
            )

        if part in ("", "."):
            continue

        clean_parts.append(
            part
        )

    if not clean_parts:
        raise InvalidContainerError(
            f"Invalid container path: {relative_path}"
        )

    return "/".join(
        clean_parts
    )


def _safe_extract_path(
    root: Path,
    relative_path: str,
) -> Path:
    normalized = _normalize_internal_path(
        relative_path
    )

    root = root.resolve()

    target = root.joinpath(
        *PurePosixPath(normalized).parts
    ).resolve(
        strict=False
    )

    if target != root and root not in target.parents:
        raise InvalidContainerError(
            f"Unsafe extraction path: {relative_path}"
        )

    return target


def _validate_header(
    header: ContainerHeader,
) -> None:
    if isinstance(header.version, bool) or not isinstance(
        header.version,
        int,
    ):
        raise InvalidContainerError(
            "Invalid container version"
        )

    if header.version != VERSION:
        raise InvalidContainerError(
            f"Unsupported container version: {header.version}"
        )

    if not isinstance(header.salt, bytes):
        raise InvalidContainerError(
            "Invalid container salt"
        )

    if len(header.salt) != EXPECTED_SALT_SIZE:
        raise InvalidContainerError(
            f"Invalid salt length: {len(header.salt)}"
        )

    if isinstance(header.iterations, bool) or not isinstance(
        header.iterations,
        int,
    ):
        raise InvalidContainerError(
            "Invalid KDF iteration count"
        )

    if header.iterations < MIN_KDF_ITERATIONS:
        raise InvalidContainerError(
            "KDF iteration count must be greater than zero"
        )

    if header.iterations > MAX_KDF_ITERATIONS:
        raise InvalidContainerError(
            "KDF iteration count exceeds TitanCrypt safety limit"
        )

    if not isinstance(header.nonce, bytes):
        raise InvalidContainerError(
            "Invalid AES-GCM nonce"
        )

    if len(header.nonce) != EXPECTED_NONCE_SIZE:
        raise InvalidContainerError(
            f"Invalid AES-GCM nonce length: {len(header.nonce)}"
        )


def _build_header_bytes(
    header: ContainerHeader,
) -> bytes:
    _validate_header(
        header
    )

    data = bytearray()

    data.extend(
        MAGIC
    )

    data.append(
        header.version & 0xFF
    )

    data.append(
        len(header.salt) & 0xFF
    )

    data.extend(
        header.salt
    )

    data.extend(
        header.iterations.to_bytes(
            4,
            byteorder="big",
            signed=False,
        )
    )

    data.append(
        len(header.nonce) & 0xFF
    )

    data.extend(
        header.nonce
    )

    return bytes(
        data
    )


def _parse_header_bytes(
    data: bytes,
    *,
    require_ciphertext: bool = True,
) -> Tuple[ContainerHeader, bytes]:
    if not isinstance(data, bytes):
        raise TypeError(
            "Container data must be bytes"
        )

    minimum_header_size = (
        len(MAGIC)
        + 1
        + 1
        + EXPECTED_SALT_SIZE
        + 4
        + 1
        + EXPECTED_NONCE_SIZE
    )

    if len(data) < minimum_header_size:
        raise InvalidContainerError(
            "Container header is truncated"
        )

    offset = 0

    magic = data[
        offset:
        offset + len(MAGIC)
    ]

    offset += len(
        MAGIC
    )

    if magic != MAGIC:
        raise InvalidContainerError(
            "Container magic identifier mismatch"
        )

    version = data[offset]
    offset += 1

    if version != VERSION:
        raise InvalidContainerError(
            f"Unsupported container version: {version}"
        )

    salt_len = data[offset]
    offset += 1

    if salt_len != EXPECTED_SALT_SIZE:
        raise InvalidContainerError(
            f"Invalid salt length: {salt_len}"
        )

    if len(data) < offset + salt_len:
        raise InvalidContainerError(
            "Container salt is truncated"
        )

    salt = data[
        offset:
        offset + salt_len
    ]

    offset += salt_len

    if len(data) < offset + 4:
        raise InvalidContainerError(
            "Container KDF field is truncated"
        )

    iterations = int.from_bytes(
        data[
            offset:
            offset + 4
        ],
        byteorder="big",
        signed=False,
    )

    offset += 4

    if iterations < MIN_KDF_ITERATIONS:
        raise InvalidContainerError(
            "Invalid KDF iteration count"
        )

    if iterations > MAX_KDF_ITERATIONS:
        raise InvalidContainerError(
            "KDF iteration count exceeds TitanCrypt safety limit"
        )

    if len(data) <= offset:
        raise InvalidContainerError(
            "AES-GCM nonce length is missing"
        )

    nonce_len = data[offset]
    offset += 1

    if nonce_len != EXPECTED_NONCE_SIZE:
        raise InvalidContainerError(
            f"Invalid AES-GCM nonce length: {nonce_len}"
        )

    if len(data) < offset + nonce_len:
        raise InvalidContainerError(
            "AES-GCM nonce is truncated"
        )

    nonce = data[
        offset:
        offset + nonce_len
    ]

    offset += nonce_len

    header = ContainerHeader(
        version=version,
        salt=salt,
        iterations=iterations,
        nonce=nonce,
    )

    _validate_header(
        header
    )

    remaining = data[
        offset:
    ]

    if require_ciphertext:
        if len(remaining) < AES_GCM_TAG_SIZE:
            raise InvalidContainerError(
                "Encrypted container payload is missing or truncated"
            )

    return (
        header,
        remaining,
    )


def _validate_manifest(
    manifest: Dict[str, Any],
    data_part: bytes,
    header: ContainerHeader | None = None,
) -> None:
    if not isinstance(manifest, dict):
        raise InvalidContainerError(
            "Manifest root must be a JSON object"
        )

    required_fields = (
        "version",
        "cipher",
        "kdf",
        "root",
        "entries",
    )

    for field in required_fields:
        if field not in manifest:
            raise InvalidContainerError(
                f"Manifest field missing: {field}"
            )

    version = manifest["version"]

    if isinstance(version, bool) or not isinstance(
        version,
        int,
    ):
        raise InvalidContainerError(
            "Manifest version must be an integer"
        )

    if version != VERSION:
        raise InvalidContainerError(
            f"Unsupported manifest version: {version}"
        )

    cipher = manifest["cipher"]

    if cipher != "AES-256-GCM":
        raise InvalidContainerError(
            f"Unsupported cipher: {cipher}"
        )

    if not isinstance(
        manifest["root"],
        str,
    ):
        raise InvalidContainerError(
            "Manifest root must be a string"
        )

    kdf = manifest["kdf"]

    if not isinstance(kdf, dict):
        raise InvalidContainerError(
            "Manifest KDF section must be an object"
        )

    if kdf.get("type") != "PBKDF2-SHA512":
        raise InvalidContainerError(
            "Unsupported manifest KDF"
        )

    kdf_iterations = kdf.get(
        "iterations"
    )

    if isinstance(
        kdf_iterations,
        bool,
    ) or not isinstance(
        kdf_iterations,
        int,
    ):
        raise InvalidContainerError(
            "Manifest KDF iterations must be an integer"
        )

    if kdf_iterations < MIN_KDF_ITERATIONS:
        raise InvalidContainerError(
            "Manifest contains invalid KDF iterations"
        )

    if kdf_iterations > MAX_KDF_ITERATIONS:
        raise InvalidContainerError(
            "Manifest KDF iterations exceed safety limit"
        )

    salt_hex = kdf.get(
        "salt_hex"
    )

    if not isinstance(
        salt_hex,
        str,
    ):
        raise InvalidContainerError(
            "Manifest KDF salt is invalid"
        )

    try:
        manifest_salt = bytes.fromhex(
            salt_hex
        )
    except ValueError as ex:
        raise InvalidContainerError(
            "Manifest KDF salt is not valid hexadecimal"
        ) from ex

    if len(manifest_salt) != EXPECTED_SALT_SIZE:
        raise InvalidContainerError(
            "Manifest KDF salt length is invalid"
        )

    if header is not None:
        if manifest_salt != header.salt:
            raise InvalidContainerError(
                "Container header and manifest salt do not match"
            )

        if kdf_iterations != header.iterations:
            raise InvalidContainerError(
                "Container header and manifest KDF iterations do not match"
            )

    entries = manifest["entries"]

    if not isinstance(
        entries,
        list,
    ):
        raise InvalidContainerError(
            "Manifest entries must be a list"
        )

    if not entries:
        raise InvalidContainerError(
            "Manifest contains no file entries"
        )

    if len(entries) > MAX_MANIFEST_ENTRIES:
        raise InvalidContainerError(
            "Manifest contains too many entries"
        )

    seen_paths: set[str] = set()

    ranges: List[
        Tuple[int, int, str]
    ] = []

    for index, entry in enumerate(
        entries
    ):
        if not isinstance(
            entry,
            dict,
        ):
            raise InvalidContainerError(
                f"Manifest entry {index} is invalid"
            )

        required_entry_fields = (
            "path",
            "size",
            "mtime",
            "offset",
            "length",
        )

        for field in required_entry_fields:
            if field not in entry:
                raise InvalidContainerError(
                    f"Manifest entry {index} is missing field: {field}"
                )

        path = _normalize_internal_path(
            entry["path"]
        )

        if path in seen_paths:
            raise InvalidContainerError(
                f"Duplicate container path: {path}"
            )

        seen_paths.add(
            path
        )

        size = entry["size"]

        if isinstance(size, bool) or not isinstance(
            size,
            int,
        ):
            raise InvalidContainerError(
                f"Invalid file size: {path}"
            )

        if size < 0:
            raise InvalidContainerError(
                f"Negative file size: {path}"
            )

        offset = entry["offset"]

        if isinstance(offset, bool) or not isinstance(
            offset,
            int,
        ):
            raise InvalidContainerError(
                f"Invalid file offset: {path}"
            )

        if offset < 0:
            raise InvalidContainerError(
                f"Negative file offset: {path}"
            )

        length = entry["length"]

        if isinstance(length, bool) or not isinstance(
            length,
            int,
        ):
            raise InvalidContainerError(
                f"Invalid file payload length: {path}"
            )

        if length < 0:
            raise InvalidContainerError(
                f"Negative file payload length: {path}"
            )

        if size != length:
            raise InvalidContainerError(
                f"File size and payload length differ: {path}"
            )

        mtime = entry["mtime"]

        if isinstance(mtime, bool) or not isinstance(
            mtime,
            (int, float),
        ):
            raise InvalidContainerError(
                f"Invalid modification timestamp: {path}"
            )

        if not math.isfinite(
            float(mtime)
        ):
            raise InvalidContainerError(
                f"Invalid modification timestamp: {path}"
            )

        end = offset + length

        if end > len(data_part):
            raise InvalidContainerError(
                f"Payload boundary exceeded: {path}"
            )

        ranges.append(
            (
                offset,
                end,
                path,
            )
        )

    for path in seen_paths:
        parts = PurePosixPath(
            path
        ).parts

        for depth in range(
            1,
            len(parts),
        ):
            parent = "/".join(
                parts[:depth]
            )

            if parent in seen_paths:
                raise InvalidContainerError(
                    f"Container contains a file/directory path collision: "
                    f"{parent} / {path}"
                )

    ranges.sort(
        key=lambda item: (
            item[0],
            item[1],
            item[2],
        )
    )

    expected_offset = 0

    for start, end, path in ranges:
        if start < expected_offset:
            raise InvalidContainerError(
                f"Overlapping payload detected: {path}"
            )

        if start > expected_offset:
            raise InvalidContainerError(
                f"Unexpected payload gap before: {path}"
            )

        expected_offset = end

    if expected_offset != len(data_part):
        raise InvalidContainerError(
            "Container contains unreferenced payload data"
        )


def _fsync_directory(
    directory: Path,
) -> None:
    if os.name == "nt":
        return

    flags = os.O_RDONLY

    if hasattr(
        os,
        "O_DIRECTORY",
    ):
        flags |= os.O_DIRECTORY

    try:
        directory_fd = os.open(
            str(directory),
            flags,
        )
    except OSError:
        return

    try:
        os.fsync(
            directory_fd
        )
    except OSError:
        pass
    finally:
        os.close(
            directory_fd
        )


def _atomic_write(
    destination: Path,
    parts: Tuple[bytes, ...],
    *,
    allow_replace: bool,
    preserve_existing_mode: bool = False,
) -> None:
    destination = Path(
        destination
    )

    parent = destination.parent

    if not parent.exists():
        raise FileNotFoundError(
            f"Destination directory does not exist: {parent}"
        )

    if not parent.is_dir():
        raise NotADirectoryError(
            str(parent)
        )

    if destination.exists() and not allow_replace:
        raise FileExistsError(
            str(destination)
        )

    existing_mode: int | None = None

    if (
        preserve_existing_mode
        and destination.exists()
    ):
        try:
            existing_mode = stat.S_IMODE(
                destination.stat().st_mode
            )
        except OSError:
            existing_mode = None

    file_descriptor = -1
    temporary_name: str | None = None

    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(parent),
        )

        with os.fdopen(
            file_descriptor,
            "wb",
        ) as output:
            file_descriptor = -1

            for part in parts:
                output.write(
                    part
                )

            output.flush()

            os.fsync(
                output.fileno()
            )

        temporary_path = Path(
            temporary_name
        )

        if existing_mode is not None:
            try:
                os.chmod(
                    temporary_path,
                    existing_mode,
                )
            except OSError:
                pass

        if destination.exists() and not allow_replace:
            raise FileExistsError(
                str(destination)
            )

        os.replace(
            temporary_path,
            destination,
        )

        temporary_name = None

        _fsync_directory(
            parent
        )

    finally:
        if file_descriptor != -1:
            try:
                os.close(
                    file_descriptor
                )
            except OSError:
                pass

        if temporary_name is not None:
            try:
                Path(
                    temporary_name
                ).unlink(
                    missing_ok=True
                )
            except OSError:
                pass


def encrypt_path(
    input_path: str,
    container_path: str,
    password: str,
    iterations: int = DEFAULT_ITERATIONS,
    overwrite: bool = False,
) -> None:
    _validate_password(
        password
    )

    _validate_iterations(
        iterations
    )

    source_path = Path(
        input_path
    )

    if not source_path.exists():
        raise FileNotFoundError(
            input_path
        )

    if source_path.is_symlink():
        raise SecureArchiveError(
            "Symbolic-link source paths are not supported"
        )

    destination = Path(
        container_path
    )

    if destination.exists() and not overwrite:
        raise FileExistsError(
            container_path
        )

    entries: List[FileEntry] = collect_entries(
        source_path
    )

    if not entries:
        raise SecureArchiveError(
            "Input path contains no files."
        )

    entries = sorted(
        entries,
        key=lambda entry: str(
            entry.rel_path
        ),
    )

    salt = generate_salt(
        EXPECTED_SALT_SIZE
    )

    kdf_parameters = KdfParams(
        iterations=iterations,
        salt=salt,
    )

    key = derive_key(
        password,
        kdf_parameters,
    )

    manifest: Dict[str, Any] = {
        "version": VERSION,
        "cipher": "AES-256-GCM",
        "kdf": {
            "type": "PBKDF2-SHA512",
            "iterations": iterations,
            "salt_hex": salt.hex(),
        },
        "root": str(
            source_path.resolve()
        ),
        "entries": [],
    }

    data_chunks = bytearray()

    current_offset = 0

    for entry in entries:
        if entry.abs_path.is_symlink():
            raise SecureArchiveError(
                f"Symbolic links are not supported: {entry.rel_path}"
            )

        if not entry.abs_path.is_file():
            raise SecureArchiveError(
                f"Source entry is not a regular file: {entry.rel_path}"
            )

        relative_path = _normalize_internal_path(
            Path(
                entry.rel_path
            ).as_posix()
        )

        try:
            with open(
                entry.abs_path,
                "rb",
            ) as source_file:
                content = source_file.read()

                file_stat = os.fstat(
                    source_file.fileno()
                )

        except OSError as ex:
            raise SecureArchiveError(
                f"Unable to read source file: {entry.rel_path}"
            ) from ex

        start_offset = current_offset

        length = len(
            content
        )

        data_chunks.extend(
            content
        )

        current_offset += length

        manifest["entries"].append(
            {
                "path": relative_path,
                "size": length,
                "mtime": file_stat.st_mtime,
                "offset": start_offset,
                "length": length,
            }
        )

    data_bytes = bytes(
        data_chunks
    )

    _validate_manifest(
        manifest,
        data_bytes,
    )

    manifest_bytes = json.dumps(
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )

    if len(manifest_bytes) > MAX_MANIFEST_SIZE:
        raise SecureArchiveError(
            "Manifest exceeds maximum allowed size"
        )

    payload = (
        manifest_bytes
        + PAYLOAD_SEPARATOR
        + data_bytes
    )

    nonce, ciphertext = encrypt_aes_gcm(
        key,
        payload,
        aad=MAGIC,
    )

    header = ContainerHeader(
        version=VERSION,
        salt=salt,
        iterations=iterations,
        nonce=nonce,
    )

    header_bytes = _build_header_bytes(
        header
    )

    _atomic_write(
        destination,
        (
            header_bytes,
            ciphertext,
        ),
        allow_replace=overwrite,
        preserve_existing_mode=overwrite,
    )


def _load_and_decrypt(
    container_path: str,
    password: str,
) -> Tuple[
    Dict[str, Any],
    bytes,
    ContainerHeader,
]:
    _validate_password(
        password
    )

    path = Path(
        container_path
    )

    if not path.exists():
        raise FileNotFoundError(
            container_path
        )

    if not path.is_file():
        raise InvalidContainerError(
            "Container path is not a regular file"
        )

    try:
        file_data = path.read_bytes()
    except OSError as ex:
        raise SecureArchiveError(
            "Unable to read encrypted container"
        ) from ex

    header, ciphertext = _parse_header_bytes(
        file_data
    )

    kdf_parameters = KdfParams(
        iterations=header.iterations,
        salt=header.salt,
    )

    key = derive_key(
        password,
        kdf_parameters,
    )

    try:
        plaintext = decrypt_aes_gcm(
            key,
            header.nonce,
            ciphertext,
            aad=MAGIC,
        )
    except InvalidTag as ex:
        raise WrongPasswordError(
            "Container authentication failed. "
            "The password may be incorrect or the container may have been modified."
        ) from ex

    try:
        manifest_part, data_part = plaintext.split(
            PAYLOAD_SEPARATOR,
            1,
        )
    except ValueError as ex:
        raise InvalidContainerError(
            "Container payload separator is missing"
        ) from ex

    if len(manifest_part) > MAX_MANIFEST_SIZE:
        raise InvalidContainerError(
            "Manifest exceeds maximum allowed size"
        )

    try:
        manifest_text = manifest_part.decode(
            "utf-8"
        )
    except UnicodeDecodeError as ex:
        raise InvalidContainerError(
            "Manifest is not valid UTF-8"
        ) from ex

    try:
        manifest = json.loads(
            manifest_text
        )
    except json.JSONDecodeError as ex:
        raise InvalidContainerError(
            "Manifest contains invalid JSON"
        ) from ex

    _validate_manifest(
        manifest,
        data_part,
        header,
    )

    return (
        manifest,
        data_part,
        header,
    )


def decrypt_container(
    container_path: str,
    output_path: str,
    password: str,
) -> None:
    manifest, data_part, _header = _load_and_decrypt(
        container_path,
        password,
    )

    output_root = Path(
        output_path
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_root = output_root.resolve()

    extraction_plan: List[
        Tuple[Dict[str, Any], Path]
    ] = []

    resolved_targets: set[str] = set()

    for entry in manifest["entries"]:
        target = _safe_extract_path(
            output_root,
            entry["path"],
        )

        collision_key = os.path.normcase(
            str(target)
        )

        if collision_key in resolved_targets:
            raise InvalidContainerError(
                f"Extraction path collision detected: {entry['path']}"
            )

        resolved_targets.add(
            collision_key
        )

        extraction_plan.append(
            (
                entry,
                target,
            )
        )

    for entry, target_path in extraction_plan:
        offset = entry["offset"]
        length = entry["length"]

        chunk = data_part[
            offset:
            offset + length
        ]

        if len(chunk) != length:
            raise InvalidContainerError(
                f"Container payload is truncated: {entry['path']}"
            )

        target_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        checked_target = _safe_extract_path(
            output_root,
            entry["path"],
        )

        if checked_target != target_path:
            raise InvalidContainerError(
                f"Extraction target changed unexpectedly: {entry['path']}"
            )

        _atomic_write(
            target_path,
            (
                bytes(chunk),
            ),
            allow_replace=True,
        )

        try:
            modification_time = float(
                entry["mtime"]
            )

            os.utime(
                target_path,
                (
                    modification_time,
                    modification_time,
                ),
            )

        except (
            OSError,
            TypeError,
            ValueError,
        ):
            pass


def list_container(
    container_path: str,
    password: str,
) -> List[Dict[str, Any]]:
    manifest, _data, _header = _load_and_decrypt(
        container_path,
        password,
    )

    return [
        dict(entry)
        for entry in manifest["entries"]
    ]


def verify_container(
    container_path: str,
    password: str,
) -> bool:
    try:
        _load_and_decrypt(
            container_path,
            password,
        )

        return True

    except (
        SecureArchiveError,
        OSError,
        TypeError,
        ValueError,
        KeyError,
        UnicodeError,
        OverflowError,
    ):
        return False


def change_password(
    container_path: str,
    old_password: str,
    new_password: str,
    iterations: int | None = None,
) -> None:
    _validate_password(
        old_password,
        "old_password",
    )

    _validate_password(
        new_password,
        "new_password",
    )

    manifest, data_part, old_header = _load_and_decrypt(
        container_path,
        old_password,
    )

    if iterations is None:
        new_iterations = old_header.iterations
    else:
        _validate_iterations(
            iterations
        )

        new_iterations = iterations

    new_salt = generate_salt(
        EXPECTED_SALT_SIZE
    )

    kdf_parameters = KdfParams(
        iterations=new_iterations,
        salt=new_salt,
    )

    key = derive_key(
        new_password,
        kdf_parameters,
    )

    manifest["kdf"] = {
        "type": "PBKDF2-SHA512",
        "iterations": new_iterations,
        "salt_hex": new_salt.hex(),
    }

    _validate_manifest(
        manifest,
        data_part,
    )

    manifest_bytes = json.dumps(
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )

    if len(manifest_bytes) > MAX_MANIFEST_SIZE:
        raise SecureArchiveError(
            "Manifest exceeds maximum allowed size"
        )

    payload = (
        manifest_bytes
        + PAYLOAD_SEPARATOR
        + data_part
    )

    nonce, ciphertext = encrypt_aes_gcm(
        key,
        payload,
        aad=MAGIC,
    )

    new_header = ContainerHeader(
        version=VERSION,
        salt=new_salt,
        iterations=new_iterations,
        nonce=nonce,
    )

    header_bytes = _build_header_bytes(
        new_header
    )

    container = Path(
        container_path
    )

    _atomic_write(
        container,
        (
            header_bytes,
            ciphertext,
        ),
        allow_replace=True,
        preserve_existing_mode=True,
    )


def inspect_container_header(
    container_path: str,
) -> Dict[str, Any]:
    path = Path(
        container_path
    )

    if not path.exists():
        raise FileNotFoundError(
            container_path
        )

    if not path.is_file():
        raise InvalidContainerError(
            "Container path is not a regular file"
        )

    try:
        with open(
            path,
            "rb",
        ) as container:
            header_data = container.read(
                HEADER_READ_SIZE
            )

        container_size = path.stat().st_size

    except OSError as ex:
        raise SecureArchiveError(
            "Unable to inspect container"
        ) from ex

    header, _remaining = _parse_header_bytes(
        header_data,
        require_ciphertext=False,
    )

    return {
        "magic": MAGIC.decode(
            "ascii"
        ),
        "version": header.version,
        "iterations": header.iterations,
        "salt_length": len(
            header.salt
        ),
        "nonce_length": len(
            header.nonce
        ),
        "container_size": container_size,
    }


def get_container_info(
    container_path: str,
    password: str,
) -> Dict[str, Any]:
    manifest, data_part, header = _load_and_decrypt(
        container_path,
        password,
    )

    entries = manifest["entries"]

    original_size = sum(
        entry["size"]
        for entry in entries
    )

    return {
        "format": MAGIC.decode(
            "ascii"
        ),
        "version": header.version,
        "cipher": manifest["cipher"],
        "kdf": manifest["kdf"]["type"],
        "iterations": header.iterations,
        "file_count": len(
            entries
        ),
        "original_size": original_size,
        "payload_size": len(
            data_part
        ),
        "container_size": Path(
            container_path
        ).stat().st_size,
    }


def verify_container_detailed(
    container_path: str,
    password: str,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": False,
        "authenticated": False,
        "format": None,
        "version": None,
        "cipher": None,
        "kdf": None,
        "iterations": None,
        "file_count": None,
        "payload_size": None,
        "container_size": None,
        "errors": [],
    }

    try:
        header_info = inspect_container_header(
            container_path
        )

        result["format"] = header_info[
            "magic"
        ]

        result["version"] = header_info[
            "version"
        ]

        result["iterations"] = header_info[
            "iterations"
        ]

        result["container_size"] = header_info[
            "container_size"
        ]

    except Exception as ex:
        result["errors"].append(
            str(ex)
        )

        return result

    try:
        manifest, data_part, header = _load_and_decrypt(
            container_path,
            password,
        )

        result["authenticated"] = True
        result["valid"] = True

        result["version"] = header.version

        result["cipher"] = manifest[
            "cipher"
        ]

        result["kdf"] = manifest[
            "kdf"
        ]["type"]

        result["iterations"] = header.iterations

        result["file_count"] = len(
            manifest["entries"]
        )

        result["payload_size"] = len(
            data_part
        )

    except WrongPasswordError as ex:
        result["errors"].append(
            str(ex)
        )

    except Exception as ex:
        result["errors"].append(
            str(ex)
        )

    return result


def read_file(
    container_path: str,
    internal_path: str,
    password: str,
) -> bytes:
    requested_path = _normalize_internal_path(
        internal_path
    )

    manifest, data_part, _header = _load_and_decrypt(
        container_path,
        password,
    )

    for entry in manifest["entries"]:
        current_path = _normalize_internal_path(
            entry["path"]
        )

        if current_path != requested_path:
            continue

        offset = entry["offset"]
        length = entry["length"]

        chunk = data_part[
            offset:
            offset + length
        ]

        if len(chunk) != length:
            raise InvalidContainerError(
                f"Payload is truncated: {requested_path}"
            )

        return bytes(
            chunk
        )

    raise FileNotFoundError(
        f"File not found in container: {internal_path}"
    )


def extract_file(
    container_path: str,
    internal_path: str,
    output_path: str,
    password: str,
) -> None:
    requested_path = _normalize_internal_path(
        internal_path
    )

    manifest, data_part, _header = _load_and_decrypt(
        container_path,
        password,
    )

    matching_entry: Dict[str, Any] | None = None

    for entry in manifest["entries"]:
        current_path = _normalize_internal_path(
            entry["path"]
        )

        if current_path == requested_path:
            matching_entry = entry
            break

    if matching_entry is None:
        raise FileNotFoundError(
            f"File not found in container: {internal_path}"
        )

    offset = matching_entry[
        "offset"
    ]

    length = matching_entry[
        "length"
    ]

    chunk = data_part[
        offset:
        offset + length
    ]

    if len(chunk) != length:
        raise InvalidContainerError(
            f"Payload is truncated: {requested_path}"
        )

    destination = Path(
        output_path
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    _atomic_write(
        destination,
        (
            bytes(chunk),
        ),
        allow_replace=True,
    )

    try:
        modification_time = float(
            matching_entry["mtime"]
        )

        os.utime(
            destination,
            (
                modification_time,
                modification_time,
            ),
        )

    except (
        OSError,
        TypeError,
        ValueError,
    ):
        pass


def find_files(
    container_path: str,
    password: str,
    pattern: str,
) -> List[Dict[str, Any]]:
    if not isinstance(
        pattern,
        str,
    ):
        raise TypeError(
            "pattern must be a string"
        )

    normalized_pattern = pattern.replace(
        "\\",
        "/",
    )

    manifest, _data, _header = _load_and_decrypt(
        container_path,
        password,
    )

    matches: List[
        Dict[str, Any]
    ] = []

    for entry in manifest["entries"]:
        internal_path = _normalize_internal_path(
            entry["path"]
        )

        if fnmatch.fnmatch(
            internal_path,
            normalized_pattern,
        ):
            matches.append(
                dict(entry)
            )

    return matches


def container_stats(
    container_path: str,
    password: str,
) -> Dict[str, Any]:
    manifest, data_part, header = _load_and_decrypt(
        container_path,
        password,
    )

    entries = manifest["entries"]

    total_size = sum(
        entry["size"]
        for entry in entries
    )

    largest_file = max(
        entries,
        key=lambda entry: entry["size"],
        default=None,
    )

    smallest_file = min(
        entries,
        key=lambda entry: entry["size"],
        default=None,
    )

    average_file_size = (
        total_size / len(entries)
        if entries
        else 0
    )

    return {
        "format": MAGIC.decode(
            "ascii"
        ),
        "version": header.version,
        "file_count": len(
            entries
        ),
        "total_size": total_size,
        "payload_size": len(
            data_part
        ),
        "container_size": Path(
            container_path
        ).stat().st_size,
        "average_file_size": average_file_size,
        "largest_file": (
            {
                "path": largest_file["path"],
                "size": largest_file["size"],
            }
            if largest_file
            else None
        ),
        "smallest_file": (
            {
                "path": smallest_file["path"],
                "size": smallest_file["size"],
            }
            if smallest_file
            else None
        ),
    }


def _prompt_new_password() -> str:
    password = getpass.getpass(
        "Password: "
    )

    confirmation = getpass.getpass(
        "Confirm password: "
    )

    if password != confirmation:
        raise SecureArchiveError(
            "Passwords do not match"
        )

    return password


def _format_size(
    size: int,
) -> str:
    value = float(
        size
    )

    units = (
        "B",
        "KiB",
        "MiB",
        "GiB",
        "TiB",
    )

    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return (
                f"{value:.2f} {unit}"
                if unit != "B"
                else f"{int(value)} B"
            )

        value /= 1024.0

    return f"{size} B"


def _create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="TitanCrypt Engine",
        description="TitanCrypt encrypted container engine",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file or directory",
    )

    encrypt_parser.add_argument(
        "input",
        help="Input file or directory",
    )

    encrypt_parser.add_argument(
        "container",
        help="Destination container",
    )

    encrypt_parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iteration count (default: {DEFAULT_ITERATIONS})",
    )

    encrypt_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing container",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a container",
    )

    decrypt_parser.add_argument(
        "container",
        help="Encrypted container",
    )

    decrypt_parser.add_argument(
        "output",
        help="Extraction directory",
    )

    list_parser = subparsers.add_parser(
        "list",
        help="List files inside a container",
    )

    list_parser.add_argument(
        "container",
        help="Encrypted container",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a container",
    )

    verify_parser.add_argument(
        "container",
        help="Encrypted container",
    )

    info_parser = subparsers.add_parser(
        "info",
        help="Display container information",
    )

    info_parser.add_argument(
        "container",
        help="Encrypted container",
    )

    info_parser.add_argument(
        "--header-only",
        action="store_true",
        help="Inspect only the public container header",
    )

    rekey_parser = subparsers.add_parser(
        "rekey",
        help="Change the container password",
    )

    rekey_parser.add_argument(
        "container",
        help="Encrypted container",
    )

    rekey_parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="Optional new PBKDF2 iteration count",
    )

    return parser


def _main() -> int:
    parser = _create_argument_parser()

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            password = _prompt_new_password()

            encrypt_path(
                args.input,
                args.container,
                password,
                iterations=args.iterations,
                overwrite=args.overwrite,
            )

            print(
                f"Container created successfully: {args.container}"
            )

            return 0

        if args.command == "decrypt":
            password = getpass.getpass(
                "Password: "
            )

            decrypt_container(
                args.container,
                args.output,
                password,
            )

            print(
                f"Container extracted successfully: {args.output}"
            )

            return 0

        if args.command == "list":
            password = getpass.getpass(
                "Password: "
            )

            entries = list_container(
                args.container,
                password,
            )

            for entry in entries:
                print(
                    f"{entry['path']} ({_format_size(entry['size'])})"
                )

            print(
                f"\nFiles: {len(entries)}"
            )

            return 0

        if args.command == "verify":
            password = getpass.getpass(
                "Password: "
            )

            result = verify_container_detailed(
                args.container,
                password,
            )

            if result["valid"]:
                print(
                    "Container verification successful."
                )

                print(
                    f"Files: {result['file_count']}"
                )

                print(
                    f"Cipher: {result['cipher']}"
                )

                print(
                    f"KDF: {result['kdf']}"
                )

                return 0

            print(
                "Container verification failed."
            )

            for error in result["errors"]:
                print(
                    f"- {error}"
                )

            return 1

        if args.command == "info":
            if args.header_only:
                info = inspect_container_header(
                    args.container
                )
            else:
                password = getpass.getpass(
                    "Password: "
                )

                info = get_container_info(
                    args.container,
                    password,
                )

            for key, value in info.items():
                if key.endswith(
                    "_size"
                ) and isinstance(
                    value,
                    int,
                ):
                    print(
                        f"{key}: {_format_size(value)}"
                    )
                else:
                    print(
                        f"{key}: {value}"
                    )

            return 0

        if args.command == "rekey":
            old_password = getpass.getpass(
                "Current password: "
            )

            new_password = getpass.getpass(
                "New password: "
            )

            confirmation = getpass.getpass(
                "Confirm new password: "
            )

            if new_password != confirmation:
                raise SecureArchiveError(
                    "New passwords do not match"
                )

            change_password(
                args.container,
                old_password,
                new_password,
                iterations=args.iterations,
            )

            print(
                "Container password changed successfully."
            )

            return 0

    except WrongPasswordError as ex:
        print(
            f"Authentication error: {ex}"
        )

        return 2

    except (
        SecureArchiveError,
        FileNotFoundError,
        FileExistsError,
        NotADirectoryError,
        PermissionError,
        ValueError,
        TypeError,
        OSError,
    ) as ex:
        print(
            f"Error: {ex}"
        )

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(
        _main()
    )
