#!/usr/bin/env python3
# KGPH

def install_pip():
    import subprocess
    import sys
    import os
    import urllib.request
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'])
    except subprocess.CalledProcessError:
        try:
            subprocess.check_call([sys.executable, '-m', 'ensurepip'])
        except subprocess.CalledProcessError:
            try:
                url = "https://bootstrap.pypa.io/get-pip.py"
                get_pip_script = "get-pip.py"
                urllib.request.urlretrieve(url, get_pip_script)
                subprocess.check_call([sys.executable, get_pip_script])
                os.remove(get_pip_script)
            except Exception as e:
                sys.exit(1)

def pip_install(package_name, upgrade=True, user=False):
    import subprocess
    import sys
    def install_package(package_name):
        try:
            command = [sys.executable, '-m', 'pip', 'install', package_name]
            if upgrade:
                command.append('--upgrade')
            if user:
                command.append('--user')
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            sys.exit(1)
    install_package(package_name)

def upgrade_pip():
    import subprocess
    import sys
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
    except subprocess.CalledProcessError as e:
        sys.exit(1)

try:
    import os
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import tarfile
    from pathlib import Path
    import urllib.request
    from github import Github
    import getpass
    import argparse
except Exception as e:
    install_pip()
    upgrade_pip()
    pip_install("cryptography")
    pip_install("PyGithub")
    import os
    import sys
    os.execv(sys.executable, [sys.executable] + sys.argv)

def encrypt_file(input_file: str, output_file: str, key_str: str, iterations=1200000):
    with open(input_file, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(key_str.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    enc_data = salt + iv + tag + ciphertext
    with open(output_file, "wb") as f:
        f.write(enc_data)

def decrypt_file(input_file: str, output_file: str, key_str: str, iterations=1200000):
    with open(input_file, "rb") as f:
        enc_data = f.read()
    salt, iv, tag, ciphertext = enc_data[:16], enc_data[16:28], enc_data[28:44], enc_data[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(key_str.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    with open(output_file, "wb") as f:
        f.write(plaintext)

def archive_folder(target_folder: str, output_archive: str):
    target_path = Path(target_folder)
    with tarfile.open(output_archive, "w:gz") as tar:
        for item in target_path.iterdir():
            tar.add(item, arcname=item.name)

def extract_archive(archive_file: str, output_folder: str):
    extract_path = Path(output_folder)
    extract_path.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_file, "r:gz") as tar:
        tar.extractall(path=extract_path)

def github_upload(token, repo_name, target_file, commit_message="Uploaded file.", topics=None, desc=None):
    g = Github(token)
    user = g.get_user()
    try:
        repo = user.get_repo(repo_name)
    except:
        repo = user.create_repo(repo_name, private=False, description=desc if desc else "")
    if desc:
        repo.edit(description=desc)
    if topics:
        repo.replace_topics(topics)
    file_name = os.path.basename(target_file)
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(target_file, "rb") as f:
            import base64
            content = base64.b64encode(f.read()).decode()
    try:
        existing_file = repo.get_contents(file_name)
        repo.update_file(existing_file.path, commit_message, content, existing_file.sha)
    except:
        repo.create_file(file_name, commit_message, content)

def github_download(author, repo, branch, target_file, binary=False):
    with urllib.request.urlopen(f"https://raw.githubusercontent.com/{author}/{repo}/{branch}/{target_file}") as response:
        file_data = response.read()
    if binary:
        import base64
        file_data = base64.b64decode(file_data)
    with open(target_file, "wb") as f:
        f.write(file_data)

def rmpkg(package, token=None):
    if token == None:
        token = getpass.getpass("Enter a Repository scope GitHub PAT. ")
    client = Github(token)
    author = client.get_user()
    package = author.get_repo(package)
    package.delete()

def get_package_info():
    package_info = """
# Knexyce Package

This repository contains a **Knexyce Package (KP)**.
Knexyce Packages are encrypted archives that provide a way to share, build, and secure data, powered by KGPH.

## What is KGPH (Knexyce GitHub Package Handler)?

**KGPH (Knexyce GitHub Package Handler)** is a lightweight Python tool for managing Knexyce Packages.

## Installing This Package

```bash
python3 kgph.py getpkg -a <author> -p <package_name> -k <encryption_key> -l <download_location>
```

Replace:

* `<author>` -> GitHub username that published the package.
* `<package_name>` -> Repository’s name.
* `<encryption_key>` -> Passphrase used to encrypt the package.
* `<download_location>` -> Folder where the package should be extracted (optional).

Make sure `kgph.py` is installed before installing this package.
"""
    return package_info

def mkpkg(folder, key=None, token=None):
    if key == None:
        key = getpass.getpass(f"Enter a passphrase to encrypt '{folder}'. ")
    if token == None:
        token = getpass.getpass("Enter a Repository scope GitHub PAT. ")
    try:
        rmpkg(folder, token)
    except:
        pass
    package_archive = f"{folder}.tar.gz"
    archive_folder(folder, package_archive)
    package_enc = f"{folder}.kgph"
    encrypt_file(package_archive, package_enc, key)
    kgph_local = os.path.basename(__file__)
    package_info = get_package_info()
    with open("README.md", "w") as f:
        f.write(package_info)
    pkg_docs = "README.md"
    github_upload(token, folder, pkg_docs, "Knexyce Package documentation manifested.")
    github_upload(token, folder, package_enc, "Knexyce Package manifested.")
    github_upload(token, folder, kgph_local, "KGPH manifested.", ["kgph", "knexyce-package", "secure", "cryptography"], "Knexyce Packages are securely encrypted archives of data managed by KGPH.")
    os.remove(package_enc)
    os.remove(package_archive)
    os.remove(pkg_docs)

def getpkg(author, package, key=None, location=None):
    if key == None:
        key = getpass.getpass(f"Enter a passphrase to decrypt '{package}'. ")
    if location is None:
        location = package
    package_enc = f"{package}.kgph"
    try:
        github_download(author, package, "main", package_enc)
    except:
        pass
    package_archive = f"{package}.tar.gz"
    decrypt_file(package_enc, package_archive, key)
    extract_archive(package_archive, location)
    os.remove(package_enc)
    os.remove(package_archive)

def main():
    parser = argparse.ArgumentParser(
        description="KGPH (Knexyce GitHub Package Handler) is a tool to handle encrypted packages."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_getpkg = subparsers.add_parser("getpkg", help="Download and decrypt a package from GitHub.")
    parser_getpkg.add_argument("-a", "--author", help="Package author.")
    parser_getpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_getpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_getpkg.add_argument("-l", "--location", help="Download path.", default=None)
    parser_mkpkg = subparsers.add_parser("mkpkg", help="Encrypt and upload a package to GitHub.")
    parser_mkpkg.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_mkpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_mkpkg.add_argument("-t", "--token", help="GitHub personal access token.", default=None)
    parser_rmpkg = subparsers.add_parser("rmpkg", help="Delete a package from GitHub.")
    parser_rmpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_rmpkg.add_argument("-t", "--token", help="GitHub personal access token.", default=None)
    args = parser.parse_args()
    if args.command == "getpkg":
        getpkg(args.author, args.package, args.key, args.location)
    elif args.command == "mkpkg":
        mkpkg(args.folder, args.key, args.token)
    elif args.command == "rmpkg":
        rmpkg(args.package, args.token)

if __name__ == "__main__":
    main()

# Author Ayan Alam (Knexyce).
# Note: Knexyce is both a group and individual.
# All rights regarding this software are reserved by Knexyce only.