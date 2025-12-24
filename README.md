<p align="center">
  <img src="https://raw.githubusercontent.com/k-auto/repo-files/main/knexyce.png" width="64" alt="Knexyce"/><br/>Knexyce
</p>

# **KDPH (Knexyce Data Package Handler)**

## **Overview**

**KDPH** is a lightweight Python tool for securely handling, distributing, and retrieving encrypted packages called **Knexyce Packages (KPs)**. It combines strong encryption, packaging, GitHub repository management, and dependency handling in one script.

* Upload: Folder (Package) -> Archival -> Encryption -> Encoding -> Cluster -> Upload
* Download: Download -> Uncluster -> Decoding -> Decryption -> Extraction -> Folder (Package)

**Key Features:**

* AES-256-GCM encryption with Argon2id key derivation.
* GitHub upload/download for files and folders.
* Large software storage via clustering.
* Automatic PIP dependency handling.

**Security Highlights:**

* Encryption increases the computational cost of brute-force attacks.
* Argon2id and AES protect against password cracking and cryptanalysis.
* Chunking allows memory-efficiency for large files.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" />
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-purple" />
  <img src="https://img.shields.io/badge/key-Argon2id-orange" />
  <img src="https://img.shields.io/badge/GitHub-repo-blueviolet" />
  <img src="https://img.shields.io/badge/dependencies-PIP-yellowgreen" />
</p>

---

## **Installation**

```bash
git clone https://github.com/Knexyce/kdph.git
cd kdph
python3 -m pip install PyGithub cryptography argon2-cffi requests
chmod +x kdph.py
```

**Requirements:** Python 3.8+

> Note: Ensure your system has network access for GitHub uploads/downloads and package installations.

---

## **Dependency Handling (PIP)**

KDPH ensures its dependencies are installed automatically:

* **`install_pip()`** – Installs pip if missing via `ensurepip` or `get-pip.py`.
* **`upgrade_pip()`** – Upgrades pip to the latest version.
* **`pip_install(package_name, upgrade=True, user=False)`** – Installs or upgrades a Python package.

This guarantees KDPH can run even on fresh systems.

---

## **Cryptography**

KDPH encrypts files using **AES-256-GCM** with an **Argon2id** key:

1. **Salt** – Randomly generated per package for unique key derivation.
2. **AES-256-GCM** – Encrypts files in **32 MB chunks**, ensuring confidentiality and integrity.

**Important Security Notes:**

* Losing the encryption key means permanent loss of data.
* Large files archives are clustered to reduce memory usage.

---

## **Hidden Utility Functions**

| Function              | Purpose                                                           |
| --------------------- | ----------------------------------------------------------------- |
| `archive_folder()`    | Compress a folder into a `.zip`.                                  |
| `extract_archive()`   | Extract a `.zip` archive.                                         |
| `github_upload()`     | Upload files/folders to GitHub (binary files are Base64-encoded). |
| `github_download()`   | Download files/folders from GitHub.                               |
| `cluster_file()`      | Split large files into 12 MB chunks with metadata.                |
| `uncluster_file()`    | Reassemble clustered chunks back into the original file.          |

These functions are used internally by the main KDPH commands.

---

## **CLI Usage**

KDPH provides three main commands:

### **1. `mkpkg` – Create & Upload a Package**

```bash
python3 kdph.py mkpkg -f <folder> -k <encryption_key> -t <github_pat>
```

Options:

* `-f, --folder` – Package folder.
* `-k, --key` – Encryption passphrase (and is prompted if omitted).
* `-t, --token` – GitHub Personal Access Token (must have `repo` scope).

### **2. `getpkg` – Download & Decrypt a Package**

```bash
python3 kdph.py getpkg -a <author> -p <package_name> -k <decryption_key> -l <download_location>
```

Options:

* `-a, --author` – GitHub username of the package author.
* `-p, --package` – Repository/package name.
* `-k, --key` – Decryption passphrase (and is prompted if omitted).
* `-l, --location` – Optional download path.

### **3. `rmpkg` – Delete a Package**

```bash
python3 kdph.py rmpkg -p <package_name> -t <github_pat>
```

Options:

* `-p, --package` – Package name (that is also the GitHub repository).
* `-t, --token` – GitHub Personal Access Token (must have `delete_repo` scope).

---

## **Workflow Example**

1. **Create a Package:**

```bash
python3 kdph.py mkpkg -f project -k key -t ghp_...
```

2. **Download a Package:**

```bash
python3 kdph.py getpkg -a Knexyce -p project -k key
```

3. **Delete a Package:**

```bash
python3 kdph.py rmpkg -p project -t ghp_...
```

---

## **Tips & Best Practices**

* Always back up your encryption key; losing it means permanent data loss.
* Use strong, high-entropy passphrases.
* Ensure your GitHub Personal Access Token has the correct scopes (which is `repo` for upload, `delete_repo` for deletion).

---

## **License & Attribution**

Author: **Ayan Alam (Knexyce)**

* Knexyce is both a group and an individual.
* All rights regarding this software are reserved by **Knexyce only**.
