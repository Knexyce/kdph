# KDPH: Knexyce Data Package Manager

**KDPH** is a lightweight package manager for managing software simply. It allows developers to package their code securely, distribute it, and retrieve it with minimal setup.

---

## Features

* Secure package encryption before upload.
* Works with Python, C, or other projects.
* Flexible package structure support.
* Code is archived, encoded, encrypted into a Knexyce Package.
* Methods to share, build, and distribute code.

---

## Example Package Structures

KDPH is flexible, but here are example layouts to help you get started.

### Python Example

```
py_example/                 # Package root.
├── __init__.py             # Handles imports.
├── __main__.py             # Entry point when run as a script.
├── config/                 # Package configurations.
│   ├── __init__.py         # Enables imports from this subpackage.
│   ├── libcfg.py           # Uses KDPH's 'getpkg' to install code into the 'lib' folder.
│   └── placeholder.json    # Example configuration file.
├── core/                   # Central package logic; may use KDPH or pip-installed code.
│   ├── __init__.py         # Enables imports from this subpackage.
│   └── placeholder.py      # Placeholder for core logic.
├── lib/                    # Location for installed packages.
│   └── __init__.py         # Enables imports from this subpackage.
└── utils/                  # Utility code.
    ├── __init__.py         # Enables imports from this subpackage.
    ├── kdph.py             # Local copy of KDPH, used by 'libcfg.py'.
    └── placeholder.py      # Placeholder utility code.
```

### C Example

```
c_example/                 # Package root; builds itself when run with 'python -m'.
├── CMakeLists.txt         # Build configuration for CMake, called from '__main__.py'.
├── __main__.py            # Installs KDPH packages into 'lib' and compiles the central project.
├── include/               # Header files.
│   └── placeholder.h      # Example header, compiled via CMake.
├── kdph.py                # Functions for installing C binaries or sources into 'lib'.
├── lib/                   # Installed dependencies.
└── src/                   # Source code files.
    └── placeholder.c      # Example source file.
```

These structures are only examples. You are free to modify them to fit your project.

---

## Installation

Clone this repository and install dependencies:

> (Bash)

```bash
git clone https://github.com/Knexyce/kdph.git
cd kdph
python3 -m pip install PyGithub cryptography
chmod +x kdph.py
./kdph.py <args>
```

---

## Usage

KDPH supports three main commands.

### 1. `getpkg` — Download and decrypt a package from GitHub.

```bash
python3 kdph.py getpkg -a <author> -p <package_name> -k <encryption_key> -l <download_location>
```

* `-a, --author` -> GitHub username.
* `-p, --package` -> Package name (which is also the GitHub repository).
* `-k, --key` -> Decryption key (and is prompted if omitted).
* `-l, --location` -> Download path (is optional).

---

### 2. `mkpkg` — Encrypt and upload a package to GitHub.

```bash
python3 kdph.py mkpkg -f <folder> -k <encryption_key> -t <github_pat>
```

* `-f, --folder` -> Package folder to archive.
* `-k, --key` -> Encryption key (and is prompted if omitted).
* `-t, --token` -> GitHub personal access token (with `repo` scope).

---

### 3. `rmpkg` — Delete a package from GitHub.

```bash
python3 kdph.py rmpkg -p <package_name> -t <github_pat>
```

* `-p, --package` -> Package name (is the GitHub repository).
* `-t, --token` -> GitHub personal access token (with `delete_repo` scope).

---

## Notes

* Python **3.8+** is required.

* GitHub personal access tokens:

  * Use the **`repo` scope** for uploading packages.
  * Use the **`delete_repo` scope** for deleting packages.

---

## License & Attribution

Author: **Ayan Alam (Knexyce)**

* Knexyce is both a group and individual.
* All rights regarding this software are reserved by **Knexyce only**.
