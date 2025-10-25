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
    import base64
    import tarfile
    from pathlib import Path
    import shutil
    import getpass
    import argparse
    import urllib.request
    import cryptography
    import argon2
    import requests
    from github import Github, Auth
except Exception as e:
    install_pip()
    upgrade_pip()
    pip_install("cryptography")
    pip_install("argon2-cffi")
    pip_install("requests")
    pip_install("PyGithub")
    import os
    import sys
    os.execv(sys.executable, [sys.executable] + sys.argv)

def encrypt_file(input_file: str, output_file: str, enc_key: str, layers: int = 4):
    import os, hashlib, hmac, tempfile
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from argon2.low_level import hash_secret_raw, Type
    CHUNK_SIZE = 16 * 1024 * 1024
    LAYERS = layers
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
    layer_keys = []
    for i in range(LAYERS):
        salt_i = salt + i.to_bytes(4, "big")
        key = hash_secret_raw(
            secret=root_key,
            salt=salt_i,
            time_cost=TIME_COST_LAYER,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=32,
            type=Type.ID
        )
        layer_keys.append(key)
    hmac_key = hashlib.sha256(root_key + b"hmac").digest()
    hm = hmac.new(hmac_key, digestmod=hashlib.sha256)
    source_path = input_file
    temp_paths = []
    try:
        for i in range(LAYERS):
            aes = AESGCMSIV(layer_keys[i])
            temp_fd, temp_path = tempfile.mkstemp()
            os.close(temp_fd)
            with open(source_path, "rb") as src, open(temp_path, "wb") as dst:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    nonce = os.urandom(12)
                    ciphertext = aes.encrypt(nonce, chunk, None)
                    dst.write(nonce)
                    dst.write(len(ciphertext).to_bytes(8, "big"))
                    dst.write(ciphertext)
            if source_path != input_file:
                try:
                    os.remove(source_path)
                except:
                    pass
            source_path = temp_path
            temp_paths.append(temp_path)
        with open(output_file, "wb") as fout, open(source_path, "rb") as src:
            fout.write(salt)
            hm.update(salt)
            while True:
                block = src.read(CHUNK_SIZE)
                if not block:
                    break
                fout.write(block)
                hm.update(block)
            fout.write(hm.digest())
    finally:
        for p in temp_paths:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except:
                pass

def decrypt_file(input_file: str, output_file: str, dec_key: str, layers: int = 4):
    import os, hashlib, hmac, tempfile
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from argon2.low_level import hash_secret_raw, Type
    CHUNK_SIZE = 16 * 1024 * 1024
    LAYERS = layers
    MEMORY_COST = 512 * 1024
    TIME_COST_ROOT = 16
    TIME_COST_LAYER = 16
    PARALLELISM = 4
    with open(input_file, "rb") as fin:
        salt = fin.read(16)
        file_data = fin.read()
        if len(file_data) < 32:
            raise ValueError()
        ciphertext_stream, expected_hmac = file_data[:-32], file_data[-32:]
    root_key = hash_secret_raw(
        secret=dec_key.encode(),
        salt=salt,
        time_cost=TIME_COST_ROOT,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=32,
        type=Type.ID
    )
    layer_keys = []
    for i in range(LAYERS):
        salt_i = salt + i.to_bytes(4, "big")
        key = hash_secret_raw(
            secret=root_key,
            salt=salt_i,
            time_cost=TIME_COST_LAYER,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=32,
            type=Type.ID
        )
        layer_keys.append(key)
    hmac_key = hashlib.sha256(root_key + b"hmac").digest()
    hm = hmac.new(hmac_key, digestmod=hashlib.sha256)
    hm.update(salt)
    hm.update(ciphertext_stream)
    if not hmac.compare_digest(hm.digest(), expected_hmac):
        raise ValueError()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(ciphertext_stream)
            temp_path = tf.name
        source_path = temp_path
        for i in reversed(range(LAYERS)):
            aes = AESGCMSIV(layer_keys[i])
            temp_fd, next_path = tempfile.mkstemp()
            os.close(temp_fd)
            with open(source_path, "rb") as src, open(next_path, "wb") as dst:
                while True:
                    nonce = src.read(12)
                    if not nonce:
                        break
                    if len(nonce) != 12:
                        raise ValueError()
                    len_bytes = src.read(8)
                    if len(len_bytes) != 8:
                        raise ValueError()
                    length = int.from_bytes(len_bytes, "big")
                    ciphertext = src.read(length)
                    if len(ciphertext) != length:
                        raise ValueError()
                    plaintext = aes.decrypt(nonce, ciphertext, None)
                    dst.write(plaintext)
            try:
                os.remove(source_path)
            except:
                pass
            source_path = next_path
        os.replace(source_path, output_file)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

def _archive_folder(target_folder: str, output_archive: str):
    target_path = Path(target_folder)
    with tarfile.open(output_archive, "w:gz") as tar:
        for item in target_path.iterdir():
            tar.add(item, arcname=item.name)

def _extract_archive(archive_file: str, output_folder: str):
    extract_path = Path(output_folder)
    extract_path.mkdir(parents=True, exist_ok=True)
    def filter_accept(tarinfo, path):
        return tarinfo
    try:
        with tarfile.open(archive_file, "r:gz") as tar:
            tar.extractall(path=extract_path, filter=filter_accept)
    except:
        with tarfile.open(archive_file, "r:gz") as tar:
            tar.extractall(path=extract_path)

def _github_upload(token, repo_name, target_path, commit_message="Uploaded file.", topics=None, desc=None):
    g = Github(auth=Auth.Token(token))
    user = g.get_user()
    try:
        repo = user.get_repo(repo_name)
    except:
        repo = user.create_repo(repo_name, private=False, description=desc or "")
    if desc:
        repo.edit(description=desc)
    if topics:
        repo.replace_topics(topics)
    base_dir = os.path.dirname(os.path.abspath(target_path)) if os.path.isdir(target_path) else os.path.dirname(target_path)
    paths_to_upload = []
    if os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                paths_to_upload.append(os.path.join(root, file))
    else:
        paths_to_upload.append(target_path)
    for local_path in paths_to_upload:
        rel_path = os.path.relpath(local_path, base_dir).replace(os.sep, "/")
        with open(local_path, "rb") as f:
            content = f.read()
        try:
            content_str = content.decode()
        except:
            content_str = base64.b64encode(content).decode()
        try:
            existing_file = repo.get_contents(rel_path)
            repo.update_file(existing_file.path, commit_message, content_str, existing_file.sha)
        except:
            repo.create_file(rel_path, commit_message, content_str)

def _github_download(author, repo_name, branch, target_path, folder_path=False, binary=False):
    if folder_path:
        api_url = f"https://api.github.com/repos/{author}/{repo_name}/contents/{target_path}?ref={branch}"
        r = requests.get(api_url)
        r.raise_for_status()
        items = r.json()
        os.makedirs(target_path, exist_ok=True)
        for item in items:
            if item["type"] == "file":
                raw_url = item["download_url"]
                local_path = os.path.join(target_path, os.path.basename(item["path"]))
                r_file = requests.get(raw_url)
                r_file.raise_for_status()
                mode = "wb" if binary else "w"
                content = r_file.content if binary else r_file.text
                with open(local_path, mode) as f:
                    f.write(content)
    else:
        raw_url = f"https://raw.githubusercontent.com/{author}/{repo_name}/{branch}/{target_path}"
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        r = requests.get(raw_url)
        r.raise_for_status()
        mode = "wb" if binary else "w"
        content = r.content if binary else r.text
        with open(target_path, mode) as f:
            f.write(content)

def _cluster_file(target_file, chunk_size=12*1024*1024):
    if not os.path.isfile(target_file):
        raise FileNotFoundError()
    folder = os.path.join(os.path.dirname(target_file), "cluster")
    os.makedirs(folder, exist_ok=True)
    name = os.path.basename(target_file)
    with open(target_file, "rb") as f:
        i = 1
        while True:
            data = f.read(chunk_size)
            if not data: break
            with open(os.path.join(folder, f"{i}.kpc"), "wb") as c:
                c.write(data)
            i += 1
    with open(os.path.join(folder, "metadata.txt"), "w") as m:
        m.write(f"{name}\n{i-1}\n")
    return folder

def _uncluster_file(target_folder):
    meta = os.path.join(target_folder, "metadata.txt")
    if not os.path.exists(meta):
        raise FileNotFoundError()
    with open(meta) as m:
        name, count = m.readline().strip(), int(m.readline().strip())
    out = os.path.join(os.path.dirname(target_folder), name)
    with open(out, "wb") as o:
        for i in range(1, count+1):
            part = os.path.join(target_folder, f"{i}.kpc")
            if not os.path.exists(part):
                raise FileNotFoundError()
            with open(part, "rb") as p:
                shutil.copyfileobj(p, o)
    shutil.rmtree(target_folder)
    return out

def _get_package_info():
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
    package_enc = f"{folder}.kp"
    pkg_docs = "README.md"
    KDPH_local = os.path.basename(__file__)
    package_info = _get_package_info()
    with open("README.md", "w") as f:
        f.write(package_info)
    _archive_folder(folder, package_archive)
    encrypt_file(package_archive, package_enc, key)
    package_cluster = _cluster_file(package_enc)
    _github_upload(token, folder, pkg_docs, "Knexyce Package documentation manifested.")
    _github_upload(token, folder, package_cluster, "Knexyce Package manifested.")
    _github_upload(token, folder, KDPH_local, "KDPH manifested.", ["knexyce", "kdph", "secure", "cryptography"], "Knexyce Packages are securely encrypted archives of data managed by KDPH.")
    shutil.rmtree(package_cluster)
    os.remove(package_enc)
    os.remove(package_archive)
    os.remove(pkg_docs)

def getpkg(author, package, key=None, location=None):
    if key is None:
        key = getpass.getpass(f"Enter a passphrase to decrypt '{package}'. ")
    if location is not None:
        location = os.path.join(location, package)
    else:
        location = package
    cluster_folder = "cluster"
    if os.path.exists(cluster_folder):
        shutil.rmtree(cluster_folder)
    _github_download(author, package, "main", cluster_folder, folder_path=True)
    package_enc = _uncluster_file(cluster_folder)
    with open(package_enc, "r") as f:
        encoded_data = f.read()
    decoded_data = base64.b64decode(encoded_data)
    with open(package_enc, "wb") as f:
        f.write(decoded_data)
    decrypt_file(package_enc, f"{package}.tar.gz", key)
    _extract_archive(f"{package}.tar.gz", location)
    os.remove(package_enc)
    os.remove(f"{package}.tar.gz")

def _main():
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
    _main()

# Author Ayan Alam (Knexyce).
# Note: Knexyce is both a group and individual.
# All rights regarding this software are reserved by Knexyce only.
