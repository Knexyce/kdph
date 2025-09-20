#!/usr/bin/env python3
# KDPH

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
    import tarfile
    from pathlib import Path
    import urllib.request
    import cryptography
    import argon2
    from github import Github, Auth
    import getpass
    import argparse
except Exception as e:
    install_pip()
    upgrade_pip()
    pip_install("cryptography")
    pip_install("argon2-cffi")
    pip_install("PyGithub")
    import os
    import sys
    os.execv(sys.executable, [sys.executable] + sys.argv)

def encrypt_file(input_file: str, output_file: str, enc_key: str):
    import os
    import hashlib
    import hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from argon2.low_level import hash_secret_raw, Type
    CHUNK_SIZE = 16 * 1024 * 1024
    LAYERS = 4
    MEMORY_COST = 512 * 1024
    TIME_COST_ROOT = 16
    TIME_COST_LAYER = 16
    PARALLELISM = 4
    salt = os.urandom(16)
    root_key = hash_secret_raw(
        secret=enc_key.encode(),
        salt=salt,
        time_cost=TIME_COST_ROOT,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=32,
        type=Type.ID
    )
    hmac_key = hashlib.sha256(root_key + b"hmac").digest()
    sha256 = hashlib.sha256()
    hm = hmac.new(hmac_key, digestmod=hashlib.sha256)
    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        fout.write(salt)
        hm.update(salt)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            layer_count_bytes = LAYERS.to_bytes(4, "big")
            fout.write(layer_count_bytes)
            sha256.update(layer_count_bytes)
            hm.update(layer_count_bytes)
            data = chunk
            for i in range(LAYERS):
                salt_i = salt + i.to_bytes(4, "big")
                key = hash_secret_raw(
                    secret=enc_key.encode(),
                    salt=salt_i,
                    time_cost=TIME_COST_LAYER,
                    memory_cost=MEMORY_COST,
                    parallelism=PARALLELISM,
                    hash_len=32,
                    type=Type.ID
                )
                iv = os.urandom(12)
                aes = AESGCMSIV(key)
                ciphertext = aes.encrypt(iv, data, None)
                length_bytes = len(ciphertext).to_bytes(8, "big")
                fout.write(iv + length_bytes + ciphertext)
                sha256.update(iv + length_bytes + ciphertext)
                hm.update(iv + length_bytes + ciphertext)
                data = ciphertext
        tag = sha256.digest()
        fout.write(tag)
        hm.update(tag)
        fout.write(hm.digest())

def decrypt_file(input_file: str, output_file: str, dec_key: str):
    import os
    import hashlib
    import hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from argon2.low_level import hash_secret_raw, Type
    LAYERS = 4
    MEMORY_COST = 512 * 1024
    TIME_COST_ROOT = 16
    TIME_COST_LAYER = 16
    PARALLELISM = 4
    with open(input_file, "rb") as fin:
        salt = fin.read(16)
        fin.seek(0, os.SEEK_END)
        total_size = fin.tell()
        fin.seek(16)
        file_data_size = total_size - 16 - 32 - 32
        root_key = hash_secret_raw(
            secret=dec_key.encode(),
            salt=salt,
            time_cost=TIME_COST_ROOT,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=32,
            type=Type.ID
        )
        hmac_key = hashlib.sha256(root_key + b"hmac").digest()
        sha256 = hashlib.sha256()
        hm = hmac.new(hmac_key, digestmod=hashlib.sha256)
        hm.update(salt)
        with open(output_file, "wb") as fout:
            processed = 0
            while processed < file_data_size:
                layer_count_bytes = fin.read(4)
                processed += 4
                sha256.update(layer_count_bytes)
                hm.update(layer_count_bytes)
                layer_count = int.from_bytes(layer_count_bytes, "big")
                layers = []
                for i in range(layer_count):
                    iv = fin.read(12)
                    length_bytes = fin.read(8)
                    length = int.from_bytes(length_bytes, "big")
                    ciphertext = fin.read(length)
                    sha256.update(iv + length_bytes + ciphertext)
                    hm.update(iv + length_bytes + ciphertext)
                    processed += 12 + 8 + length
                    layers.append((iv, ciphertext, i))
                data = None
                for iv, ciphertext, i in reversed(layers):
                    salt_i = salt + i.to_bytes(4, "big")
                    key = hash_secret_raw(
                        secret=dec_key.encode(),
                        salt=salt_i,
                        time_cost=TIME_COST_LAYER,
                        memory_cost=MEMORY_COST,
                        parallelism=PARALLELISM,
                        hash_len=32,
                        type=Type.ID
                    )
                    aes = AESGCMSIV(key)
                    plaintext = aes.decrypt(iv, ciphertext, None)
                    data = plaintext
                fout.write(data)
            expected_tag = fin.read(32)
            hm.update(expected_tag)
            if sha256.digest() != expected_tag:
                raise ValueError()
            expected_hmac = fin.read(32)
            if not hmac.compare_digest(hm.digest(), expected_hmac):
                raise ValueError()

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
    g = Github(auth=Auth.Token(token))
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

def get_package_info():
    package_info = """
# Knexyce Package

This repository contains a **Knexyce Package (KP)**.
Knexyce Packages are encrypted archives that provide a way to share, build, and secure data, powered by KDPH.

## What is KDPH (Knexyce Data Package Handler)?

**KDPH (Knexyce Data Package Handler)** is a lightweight Python tool for managing Knexyce Packages.

## Installing This Package

```bash
python3 kdph.py getpkg -a <author> -p <package_name>
```

Replace:

* `<author>` -> GitHub username that uploaded the package.
* `<package_name>` -> Repository’s name.

Ensure `kdph.py` is installed before installing this package.
"""
    return package_info

def rmpkg(package, token=None):
    if token == None:
        token = getpass.getpass("Enter a repository deletion scope GitHub PAT. ")
    client = Github(auth=Auth.Token(token))
    author = client.get_user()
    package = author.get_repo(package)
    package.delete()

def mkpkg(folder, key=None, token=None):
    if key == None:
        key = getpass.getpass(f"Enter a passphrase to encrypt '{folder}'. ")
    if token == None:
        token = getpass.getpass("Enter a repository scope GitHub PAT. ")
    try:
        rmpkg(folder, token)
    except:
        pass
    package_archive = f"{folder}.tar.gz"
    archive_folder(folder, package_archive)
    package_enc = f"{folder}.kdph"
    encrypt_file(package_archive, package_enc, key)
    KDPH_local = os.path.basename(__file__)
    package_info = get_package_info()
    with open("README.md", "w") as f:
        f.write(package_info)
    pkg_docs = "README.md"
    github_upload(token, folder, pkg_docs, "Knexyce Package documentation manifested.")
    github_upload(token, folder, package_enc, "Knexyce Package manifested.")
    github_upload(token, folder, KDPH_local, "KDPH manifested.", ["kdph", "knexyce-package", "secure", "cryptography"], "Knexyce Packages are securely encrypted archives of data managed by KDPH.")
    os.remove(package_enc)
    os.remove(package_archive)
    os.remove(pkg_docs)

def getpkg(author, package, key=None, location=None):
    if key == None:
        key = getpass.getpass(f"Enter a passphrase to decrypt '{package}'. ")
    if location is None:
        location = package
    package_enc = f"{package}.kdph"
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
        description="KDPH (Knexyce Data Package Handler) is a tool to handle encrypted packages."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_getpkg = subparsers.add_parser("getpkg", help="Download and decrypt a package from GitHub.")
    parser_getpkg.add_argument("-a", "--author", help="Package author.")
    parser_getpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_getpkg.add_argument("-k", "--key", help="Decryption key.")
    parser_getpkg.add_argument("-l", "--location", help="Download path.", default=None)
    parser_mkpkg = subparsers.add_parser("mkpkg", help="Encrypt and upload a package to GitHub.")
    parser_mkpkg.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_mkpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_mkpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
    parser_rmpkg = subparsers.add_parser("rmpkg", help="Delete a package from GitHub.")
    parser_rmpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_rmpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
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
