# KDPH (Knexyce Data Package Handler)

## Overview

**KDPH (Knexyce Data Package Handler)** is a Python operating system agnostic package manager designed to securely create, distribute, retrieve, and manage encrypted data packages known as **Knexyce Packages (KPs)**.

KDPH combines modern cryptography, reproducible packaging, and GitHub-backed distribution into a single self-contained tool. It is suitable for secure data delivery, modular project distribution, controlled software packaging, and encrypted archival workflows.

A Knexyce Package (`.kp`) is an encrypted archive that can contain arbitrary files, metadata, build instructions, and dependency references. KDPH manages the full lifecycle of these packages.

---

## Key Features

* Strong encryption using AES-GCM with Argon2id key derivation.
* Deterministic package structure.
* GitHub-based package distribution.
* Built-in dependency resolution.
* Package metadata querying.
* No platform-specific dependencies.

---

## Installation

KDPH requires Python 3.9 or newer.

### Unix-like Systems (Linux, macOS)

```bash
curl https://raw.githubusercontent.com/Knexyce/kdph/main/kdph.py -o kdph.py
```

### Windows (PowerShell)

```powershell
curl https://raw.githubusercontent.com/Knexyce/kdph/main/kdph.py -OutFile kdph.py
```

Run commands using:

```bash
python kdph.py <command> [options]
```

KDPH automatically installs all required Python dependencies on first execution.

---

## Command Overview

KDPH provides the following primary commands:

* `mkpkg`     : Encrypt and publish a package to GitHub.
* `getpkg`    : Download and decrypt a package from GitHub.
* `rmpkg`     : Delete a package repository from GitHub.
* `createkp`  : Create a local encrypted package.
* `extractkp` : Decrypt and extract a local package.
* `kpinfo`    : Query metadata from an extracted package.

Each command is documented below.

---

## mkpkg

### Description

Creates an encrypted Knexyce Package from a folder and uploads it to GitHub as a repository.

This command:

* Encrypts the folder into a `.kp` file.
* Base64-encodes the package.
* Splits the package into clustered chunks.
* Uploads the chunks and documentation to GitHub.
* Publishes the KDPH script alongside the package.

### Usage

```bash
python kdph.py mkpkg -f <folder> [-k <key>] [-t <github_token>]
```

### Arguments

* `-f, --folder`   : Folder to package.
* `-k, --key`      : Encryption key (prompted if omitted).
* `-t, --token`    : GitHub Personal Access Token.

The token must have `repo` and `delete_repo` scopes.

---

## getpkg

### Description

Downloads, reconstructs, decrypts, and extracts a Knexyce Package from GitHub.

This command:

* Downloads clustered package files.
* Reassembles and decodes the package.
* Verifies KDPH integrity.
* Decrypts the package.
* Resolves dependencies.
* Executes the package build script.

### Usage

```bash
python kdph.py getpkg -a <author> -p <package> [-l <location>] [-k <key>]
```

### Arguments

* `-a, --author`   : GitHub username of the package author.
* `-p, --package`  : Package repository name.
* `-l, --location` : Extraction directory.
* `-k, --key`      : Decryption key (prompted if omitted).

---

## rmpkg

### Description

Deletes a Knexyce Package repository from GitHub.

### Usage

```bash
python kdph.py rmpkg -p <package> [-t <github_token>]
```

### Arguments

* `-p, --package` : Package repository name.
* `-t, --token`   : GitHub Personal Access Token.

The token must have the `delete_repo` scope.

---

## createkp

### Description

Creates a local encrypted `.kp` file without uploading it to GitHub.

This command:

* Initializes the `kpcore` structure if missing.
* Generates or updates metadata.
* Encrypts the folder.
* Appends a KDPH integrity signature.

### Usage

```bash
python kdph.py createkp -f <folder> [-l <location>] [-k <key>]
```

### Arguments

* `-f, --folder`   : Folder to package.
* `-l, --location` : Output directory.
* `-k, --key`      : Encryption key (prompted if omitted).

---

## extractkp

### Description

Decrypts and extracts a local `.kp` file.

This command:

* Verifies client-side and package integrity.
* Decrypts the package.
* Extracts contents.
* Resolves dependencies.
* Executes the package build script.

### Usage

```bash
python kdph.py extractkp -p <package.kp> [-l <location>] [-k <key>]
```

### Arguments

* `-p, --package`  : Path to the `.kp` file.
* `-l, --location` : Extraction directory.
* `-k, --key`      : Decryption key (prompted if omitted).

---

## kpinfo

### Description

Queries metadata from an extracted Knexyce Package.

### Usage

```bash
python kdph.py kpinfo -f <folder> -t <topic>
```

### Arguments

* `-f, --folder` : Extracted package folder.
* `-t, --topic`  : Metadata field name.

Example topics include `name`, `version`, `author`, `description`, and `created_at`.

---

## KPCore Structure

Each Knexyce Package contains a `kpcore` directory that defines package behavior.

### Files

* `build.py`
  Executed after extraction to configure or build the package.

* `pkgdeps.json`
  Declares package dependencies. Dependencies can be GitHub-hosted packages or local `.kp` files.

* `metadata.json`
  Stores package metadata such as name, version, author, and timestamps.

* `ignore.txt`
  Defines paths excluded from packaging.

* `kdph.py`
  Embedded copy of the KDPH script used to create the package.

* `INFO.md`
  Informational documentation about the package core.

---

## Cryptography Model

KDPH uses modern, secure cryptographic primitives:

* AES-256-GCM for authenticated encryption.
* Argon2id for password-based key derivation.
* Per-chunk random salts and nonces.
* Automatic key rotation for large files.
* Optional multi-layer encryption (if manual).
* Eradicated birthday bound nonce reuse risk by rekey every 12 GB.

All encryption and decryption is performed locally. No plaintext package contents are uploaded to GitHub.

---

## GitHub Handling

KDPH uses GitHub as a package transport layer, not as a trust authority.

* Packages are uploaded as repositories.
* Encrypted data is stored as clustered binary chunks.
* Integrity is enforced via embedded KDPH hash verification.
* GitHub tokens are never stored persistently.
* A copy of KDPH is uploaded with the package.

---

## Operating System Compatibility

KDPH is fully OS agnostic.

* Any OS with Python.

All file operations, cryptography, and networking are handled through cross-platform Python libraries.

---

## Security Notes

* Loss of the encryption key makes recovery impossible.
* Package integrity is bound to the KDPH script used to create it.
* Always verify the source of `kdph.py` before use.
* Use strong, high-entropy passphrases. 
* Minimum is an eight-character passphrase with a symbol, capital letter, and number.

---

## License and Rights

- All rights regarding this software are reserved by Knexyce only.
- Knexyce refers to both an individual and a group entity.
- Unauthorized redistribution, modification, or misuse is prohibited. We don't want security risks.

## Author

Ayan Alam (Knexyce)
