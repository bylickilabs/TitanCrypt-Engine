| ![Build](https://img.shields.io/github/actions/workflow/status/bylickilabs/TitanCrypt-Engine/main.yml?label=Build&logo=github) | ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) | ![License](https://img.shields.io/badge/License-MIT-success) | ![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen) | ![Security](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20PBKDF2--SHA512-critical) | ![Maintained](https://img.shields.io/badge/Maintained%20by-BYLICKILABS-%2300aaff) |
|---|---|---|---|---|---|

# TitanCrypt Engine  
_Modular Encrypted Container Engine for Python — Powered by BYLICKILABS_

| <img width="1280" height="640" alt="TCE" src="https://github.com/user-attachments/assets/612bf24e-3d02-4329-be8c-49eee2d208e9" /> |
|---|

> TitanCrypt Engine provides secure, high-performance encryption for entire directory structures by packaging them into a single, authenticated container file.

> Designed for developers who need reliable data protection, integrity validation, and seamless integration into modern Python applications.

<br>

---

<br>

### Integration Announcement
  - TitanCrypt Engine is already fully integrated into SecureArchive.
  - The latest production release of SecureArchive ships with TitanCrypt Engine as the core encryption and container-management system.

> This ensures:
- End-to-end encryption using AES-256-GCM
- Strong password-based security via PBKDF2-SHA-512
- Verified container integrity across all stored data
- Seamless extraction, validation and password rotation support

---

📦 Included in Release:
> SecureArchive v1.0.1
🔗 [RELEASE](https://github.com/bylickilabs/SecureArchive/releases/download/v1.0.1/v1.0.1.rar)

> Source Repository v1.0.0:
🔧 [LINK](https://github.com/bylickilabs/SecureArchive)

---

> TitanCrypt Engine now powers the secure container functionality of SecureArchive.
  - delivering real-world encryption for production environments, backed by continuous development from BYLICKILABS.
    - “Same engine. More security. Ready for deployment.”

<br>

---

<br>

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Use Cases](#use-cases)
- [Architecture](#architecture)
  - [Modules](#modules)
  - [Security Model](#security-model)
  - [Container Format](#container-format)
- [Installation](#installation)
- [Public API](#public-api)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

<br>

---

<br>

## Overview

> TitanCrypt Engine is a **production-ready**, developer-focused encryption library built in Python.

It enables:

- Secure backups
- Confidential document storage
- Encrypted transfer of data packages
- DevOps artifact protection
- Infrastructure-independent container security

Its architecture cleanly separates:

| Module | Responsibility |
|--------|----------------|
| `engine.py` | Public API & container operations |
| `crypto.py` | Key derivation & AES-GCM encryption |
| `fsutil.py` | File indexing & metadata management |

This creates a lightweight, scalable foundation for long-term product integration.

<br>

---

<br>

## Key Features

- 🔐 **AES-256-GCM Encryption**
  - Authenticated encryption with integrity protection
- 🔑 **PBKDF2-SHA-512 key derivation**
  - Configurable iteration count for improved resilience
- 📦 **Encrypted container format**
  - Single secure file containing multiple directory entries
- 🧩 **Modular architecture**
  - Crypto and filesystem logic cleanly separated
- ⚙️ **Developer-first Python API**
  - No external binaries required
- 🛡️ **Integrity validation**
  - Verifies container consistency and offsets
- 🔁 **Password rotation**
  - Re-encrypt containers without re-packaging files

<br>

---

<br>

## Use Cases

| Scenario | Benefit |
|---------|---------|
| Secure DevOps pipelines | Protect build artifacts and deployments |
| Enterprise compliance | Encrypted archiving of sensitive records |
| Cross-environment data transfer | Safeguard assets in motion |
| Private data protection | Confidential backups and local archives |

<br>

---

<br>

## Architecture

### Modules

#### `engine.py`
High-level container engine:
- Build/read/verify encrypted containers
- API exposed to application developers
- Custom exception classes:
  - `SecureArchiveError`
  - `InvalidContainerError`
  - `WrongPasswordError`

#### `crypto.py`
Security implementation:
- AES-256-GCM encryption/decryption
- PBKDF2-SHA-512 key derivation
- Secure randomness (nonce & salt)

#### `fsutil.py`
Filesystem traversal:
- Recursively collects file paths
- Metadata: size, mtime, relative offsets

<br>

---

<br>

## Security Model

| Component | Technology |
|----------|------------|
| Encryption | AES-256-GCM (AEAD) |
| Key derivation | PBKDF2-SHA-512 |
| AAD | `MAGIC = b"SECARC01"` |
| Nonce | 96-bit random per container |
| Salt | 128-bit unique per container |

✔ Prevents header tampering  
✔ Authenticates ciphertext and metadata  
✔ Defends against offline brute-force attacks (configurable iteration count)

<br>

---

<br>

## Container Format

> TitanCrypt Engine stores encrypted data inside a **compact binary container** designed for long-term security,
  - integrity validation, and portability across systems.

### Physical Layout


The **header** is unencrypted and contains the cryptographic metadata required for decryption:

| Header Field | Description |
|-------------|-------------|
| Magic | Identifier of the format (`SECARC01`) |
| Version | Container version (1 byte) |
| Salt-Length | Size of the salt field |
| Salt | Unique random salt for KDF |
| Iterations | PBKDF2 iteration count |
| Nonce-Length | Size of AES-GCM nonce |
| Nonce | 96-bit random nonce |

➡ Following the header, the rest of the file is **AES-256-GCM ciphertext**.

---

### Logical Decrypted Payload


The **manifest** is UTF-8 JSON and includes:

| Key | Meaning |
|-----|--------|
| `root` | Base directory of the encrypted content |
| `entries` | File descriptions (path, size, offset, mtime, length) |
| `cipher` | Crypto algorithm (AES-256-GCM) |
| `kdf` | KDF parameters used (salt, iterations) |
| `version` | Schema version |

📌 The **payload separator** ensures reliable parsing:


➡ Everything after this marker is a **binary concatenation** of file data — in the order defined by `entries`.

---

### Benefits & Guarantees

| Feature | Benefit |
|--------|---------|
| Single secure file | No loose sensitive data on storage |
| Integrity protection | GCM authentication validates whole container |
| Scalable | Efficient mapping for thousands of files |
| Password rotation | Re-encryption without rebuilding structure |
| No dependency on platform | Fully self-contained format |

---

**In summary:**  
> A secure, structured and verifiable encryption format designed for real-world data protection and DevOps environments.

<br>

---

<br>

## Installation

TitanCrypt Engine requires Python **3.10+** and the `cryptography` library.

### Option 1 — Local integration (recommended during development)

> Clone or download this repository and include the module in your Python project:

```yarn
titancrypt_engine/
├─ engine.py
├─ crypto.py
├─ fsutil.py
└─ init.py
```


Install required dependency:

```yarn
pip install cryptography
```

<br>

---

<br>

## Public API

> TitanCrypt Engine exposes a clean and minimal Python interface designed for direct integration into applications, automation pipelines, and security tooling.
  - Below is a summary of the main public functions and their intended use.

---

### `encrypt_path(input_path, container_path, password, iterations=300_000, overwrite=False) -> None`

Creates a new encrypted container file from a directory.

| Parameter | Type | Description |
|----------|------|-------------|
| `input_path` | str/Path | Directory to encrypt |
| `container_path` | str/Path | Output `.tcrypt` file |
| `password` | str | User-defined encryption password |
| `iterations` | int | PBKDF2 iteration count |
| `overwrite` | bool | Replace existing container if true |

Raises:
- `SecureArchiveError` if encryption fails

---

### `decrypt_container(container_path, output_path, password) -> None`

Extracts and decrypts a container file into the specified output directory.

Raises:
- `WrongPasswordError` if authentication fails
- `InvalidContainerError` if file is corrupted or incompatible

---

### `list_container(container_path, password) -> List[Dict[str, Any]]`

Loads container metadata **without extracting files**.

| Key Returned | Description |
|--------------|-------------|
| `path` | File path inside container |
| `size` | File size (bytes) |
| `mtime` | Last modified timestamp |
| `offset` | Raw payload start position |
| `length` | Raw payload length in bytes |

Useful for audits and quick validation.

---

### `verify_container(container_path, password) -> bool`

Validates both:
- ❏ Password correctness  
- ❏ Structural integrity (offsets, lengths, authentication tag)

Returns:
- `True` if container is valid  
- `False` otherwise

---

### `change_password(container_path, old_password, new_password, iterations=None) -> None`

Re-encrypts the container with a new password and optionally updates PBKDF2 iteration count.

✔ No need to decrypt files to disk  
✔ Maintains secure metadata and payload structure  
✔ Ideal for periodic security rotation policies

---

## Exception Classes

| Exception | Trigger |
|----------|---------|
| `SecureArchiveError` | General engine-level failure |
| `WrongPasswordError` | AES-GCM authentication failed |
| `InvalidContainerError` | Header, manifest or payload corruption |



<br>

---

<br>

## Error Handling

TitanCrypt Engine provides clear and predictable exception types, enabling professional error management in automation workflows, CI/CD pipelines, and security-critical applications.

All errors inherit from:

- `SecureArchiveError` — Base class for engine-related failures

Specific exception classes:

| Exception | Trigger / Meaning |
|----------|------------------|
| `WrongPasswordError` | AES-GCM authentication failed → incorrect password or manipulated data |
| `InvalidContainerError` | Container header, manifest, or payload corrupted — structural or version mismatch |
| `SecureArchiveError` | General operational failure not covered by other exceptions |

<br>

---

<br>

## Best Practices

To ensure strong and dependable security when using TitanCrypt Engine, the following operational guidelines are recommended:

---

### 🔑 Password / Key Security

- Always use **strong passphrases** (≥ 20 characters)
- Prefer randomly generated passwords over human-readable strings
- Avoid reusing passwords across multiple containers or systems
- Store passwords securely using:
  - Hardware tokens
  - Secure password vaults
  - Environment-based secret injection

---

### 🔁 KDF Iteration Strength

- Increase PBKDF2 iteration count based on hardware performance
- Recommended minimum: `300_000` iterations  
- For powerful servers: `500_000 – 1_000_000+`

Higher iteration count = stronger brute-force mitigation ✔

---

### 🧪 Integrity & Validation

- Run `verify_container()`:
  - after network transfer  
  - before critical usage  
  - in automated backup workflows  
- Treat **any failed validation** as a **security risk**

---

### 🗂 Data & Container Handling

- Never edit encrypted container files manually  
- Avoid using network shares without integrity checks  
- Maintain **container version compatibility** in CI/CD

Good practice for DevOps pipelines:

```yarn
verify_container secure.tcrypt
```

---
