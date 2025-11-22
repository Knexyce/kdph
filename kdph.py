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
    import zipfile
    from pathlib import Path
    import shutil
    import subprocess
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

def encrypt_file(input_file, output_file, key):
    import os, tempfile, hmac, hashlib, struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
    chunk_size = 16 * 1024 * 1024
    argon_mem, argon_time, argon_parallel, key_len = 768 * 1024, 32, 8, 32
    salt = os.urandom(16)
    derived = hash_secret_raw(key.encode(), salt, argon_time, argon_mem, argon_parallel, key_len, Type.ID)
    hmac_key = hashlib.sha256(b"HMAC" + derived).digest()
    total = 0
    next_salt_marker = None
    temp_fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(temp_fd, 'wb') as tmp, open(input_file, 'rb') as fin:
            tmp.write(salt)
            h = hmac.new(hmac_key, digestmod=hashlib.sha256)
            h.update(salt)
            while True:
                data = fin.read(chunk_size)
                if not data:
                    break
                if next_salt_marker:
                    tmp.write(next_salt_marker)
                    h.update(next_salt_marker)
                    next_salt_marker = None
                nonce = os.urandom(12)
                aesgcm = AESGCM(derived)
                enc = aesgcm.encrypt(nonce, data, None)
                tmp.write(struct.pack('I', len(enc)))
                tmp.write(nonce)
                tmp.write(enc)
                h.update(struct.pack('I', len(enc)))
                h.update(nonce)
                for i in range(0, len(enc), 1024*1024):
                    h.update(enc[i:i+1024*1024])
                total += len(data)
                if total >= 12 * 1024 * 1024 * 1024:
                    salt = os.urandom(16)
                    derived = hash_secret_raw(key.encode(), salt, argon_time, argon_mem, argon_parallel, key_len, Type.ID)
                    hmac_key = hashlib.sha256(b"HMAC" + derived).digest()
                    next_salt_marker = b'\x00KXSALT' + salt
                    total = 0
        with open(output_file, 'wb') as fout, open(temp_path, 'rb') as tf:
            fout.write(tf.read())
            fout.write(h.digest())
    finally:
        if os.path.exists(temp_path):
            filesize = os.path.getsize(temp_path)
            with open(temp_path, 'r+b') as f:
                f.seek(0)
                f.write(b'\x00' * filesize)
                f.flush()
                os.fsync(f.fileno())
            os.remove(temp_path)

def decrypt_file(input_file, output_file, key):
    import os, tempfile, hmac, hashlib, struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
    argon_mem, argon_time, argon_parallel, key_len = 768 * 1024, 32, 8, 32
    filesize = os.path.getsize(input_file)
    with open(input_file, 'rb') as fin:
        fin.seek(filesize - 32)
        tag = fin.read(32)
    salt = None
    with open(input_file, 'rb') as fin:
        salt = fin.read(16)
        derived = hash_secret_raw(key.encode(), salt, argon_time, argon_mem, argon_parallel, key_len, Type.ID)
        hmac_key = hashlib.sha256(b"HMAC" + derived).digest()
        h = hmac.new(hmac_key, digestmod=hashlib.sha256)
        fin.seek(0)
        total_read = 0
        while total_read < filesize - 32:
            read_size = min(1024*1024, filesize - 32 - total_read)
            data_chunk = fin.read(read_size)
            if not data_chunk:
                break
            h.update(data_chunk)
            total_read += len(data_chunk)
    if not hmac.compare_digest(h.digest(), tag):
        raise ValueError()
    temp_fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(temp_fd, 'wb') as tmp:
            with open(input_file, 'rb') as fin:
                tmp.write(fin.read(filesize - 32))
        with open(temp_path, 'rb') as tf, open(output_file, 'wb') as fout:
            salt = tf.read(16)
            derived = hash_secret_raw(key.encode(), salt, argon_time, argon_mem, argon_parallel, key_len, Type.ID)
            hmac_key = hashlib.sha256(b"HMAC" + derived).digest()
            while True:
                marker = tf.read(8)
                if not marker:
                    break
                if marker == b'\x00KXSALT':
                    salt = tf.read(16)
                    derived = hash_secret_raw(key.encode(), salt, argon_time, argon_mem, argon_parallel, key_len, Type.ID)
                    hmac_key = hashlib.sha256(b"HMAC" + derived).digest()
                    continue
                tf.seek(-8, 1)
                length_data = tf.read(4)
                if not length_data:
                    break
                length = struct.unpack('I', length_data)[0]
                nonce = tf.read(12)
                enc = tf.read(length)
                aesgcm = AESGCM(derived)
                fout.write(aesgcm.decrypt(nonce, enc, None))
    finally:
        if os.path.exists(temp_path):
            filesize = os.path.getsize(temp_path)
            with open(temp_path, 'r+b') as f:
                f.seek(0)
                f.write(b'\x00' * filesize)
                f.flush()
                os.fsync(f.fileno())
            os.remove(temp_path)

def archive_folder(target_folder: str, output_archive: str):
    target_path = Path(target_folder)
    base_name = target_path.name
    with zipfile.ZipFile(output_archive, "w", zipfile.ZIP_DEFLATED) as z:
        for p in target_path.rglob("*"):
            z.write(p, arcname=str(Path(base_name) / p.relative_to(target_path)))

def extract_archive(archive_file: str, extraction_path: str):
    output = Path(extraction_path).parent
    with zipfile.ZipFile(archive_file, "r") as z:
        z.extractall(path=output)

def github_upload(token, repo_name, target_path, commit_message="Uploaded file.", topics=None, desc=None):
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
    base_dir = os.path.dirname(os.path.abspath(target_path))
    paths_to_upload = []
    if os.path.isdir(target_path):
        for file in os.listdir(target_path):
            file_path = os.path.join(target_path, file)
            if os.path.isfile(file_path):
                paths_to_upload.append(file_path)
    else:
        paths_to_upload.append(target_path)
    for local_path in paths_to_upload:
        rel_path = os.path.relpath(local_path, base_dir).replace(os.sep, "/")
        with open(local_path, "rb") as f:
            content = f.read()
        try:
            content_str = content.decode()
        except:
            content_str = content
        try:
            existing_file = repo.get_contents(rel_path)
            repo.update_file(existing_file.path, commit_message, content_str, existing_file.sha)
        except:
            repo.create_file(rel_path, commit_message, content_str)

def github_download(author, repo_name, branch, target_path, folder_path=False, binary=False):
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

def cluster_file(target_file, output_folder="cluster", chunk_size=12*1024*1024):
    if not os.path.isfile(target_file):
        raise FileNotFoundError()
    folder = os.path.join(os.path.dirname(target_file), output_folder)
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

def uncluster_file(target_folder):
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

def createkp(folder, key=None):
    folder_path = os.path.abspath(os.path.normpath(folder))
    folder_name = os.path.basename(folder_path.rstrip(os.sep))
    if key is None:
        key = getpass.getpass(f"Enter a passphrase to encrypt '{folder_name}'. ")
    kbuild_path = os.path.join(folder_path, "kbuild.py")
    if not os.path.exists(kbuild_path):
        with open(kbuild_path, "w") as f:
            f.write("""#!/usr/bin/env python3
# KBuild

# "kbuild.py" identifies a folder as a Knexyce Package (KP) and is auto-generated if missing.
# Replace these comments with configuration and package-building code, then run "mkpkg" to upload.
# "getpkg" will execute this file to configure and build the package.""")
    archive_file = f"{folder_name}.zip"
    archive_folder(folder_path, archive_file)
    kp_file = f"{folder_name}.kp"
    encrypt_file(archive_file, kp_file, key)
    os.remove(archive_file)

def openkp(package, key=None, location=None):
    if key is None:
        key = getpass.getpass(f"Enter a passphrase to decrypt '{package}'. ")
    package_name = Path(package).stem
    if location is None:
        location = package_name
    location = os.path.abspath(location)
    os.makedirs(location, exist_ok=True)
    decrypted_archive = f"{package_name}.zip"
    decrypt_file(package, decrypted_archive, key)
    extract_archive(decrypted_archive, location)
    os.remove(decrypted_archive)
    kbuild_path = os.path.join(location, "kbuild.py")
    kbuild_cwd = os.path.dirname(kbuild_path)
    subprocess.run([os.sys.executable, kbuild_path], cwd=kbuild_cwd, check=True)

def rmpkg(package, token=None):
    if token == None:
        token = getpass.getpass("Enter a repository deletion scope GitHub PAT. ")
    client = Github(auth=Auth.Token(token))
    author = client.get_user()
    package = author.get_repo(package)
    package.delete()

def mkpkg(folder, key=None, token=None):
    folder_path = os.path.abspath(os.path.normpath(folder))
    folder_name = os.path.basename(folder_path.rstrip(os.sep))
    if token == None:
        token = getpass.getpass("Enter a repository scope GitHub PAT. ")
    try:
        rmpkg(folder_name, token)
    except:
        pass
    package_enc = f"{folder_name}.kp"
    pkg_docs = "README.md"
    kdph_local = os.path.abspath(__file__)
    package_info = """# Knexyce Package

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

Ensure `kdph.py` is installed before installing this package."""
    with open("README.md", "w") as f:
        f.write(package_info)
    createkp(folder, key)
    with open(package_enc, "rb") as f:
        encoded = base64.b64encode(f.read())
    with open(package_enc, "wb") as f:
        f.write(encoded)
    package_cluster = cluster_file(package_enc)
    github_upload(token, folder_name, pkg_docs, "Knexyce Package documentation manifested.")
    github_upload(token, folder_name, package_cluster, "Knexyce Package manifested.")
    github_upload(token, folder_name, kdph_local, "KDPH manifested.", ["knexyce-package"], "Knexyce Packages are securely encrypted archives of data managed by KDPH.")
    shutil.rmtree(package_cluster)
    os.remove(package_enc)
    os.remove(pkg_docs)

def getpkg(author, package, key=None, location=None):
    if location is not None:
        location = os.path.join(location, package)
    else:
        location = package
    cluster_folder = "cluster"
    if os.path.exists(cluster_folder):
        shutil.rmtree(cluster_folder)
    github_download(author, package, "main", cluster_folder, folder_path=True, binary=True)
    package_enc = uncluster_file(cluster_folder)
    with open(package_enc, "rb") as f:
        encoded_data = f.read()
    decoded_data = base64.b64decode(encoded_data)
    with open(package_enc, "wb") as f:
        f.write(decoded_data)
    openkp(package_enc, key, location)
    os.remove(package_enc)

def main():
    parser = argparse.ArgumentParser(
        prog="KDPH",
        description="KDPH (Knexyce Data Package Handler) is a tool to handle encrypted packages."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_getpkg = subparsers.add_parser("getpkg", help="Download and decrypt a package from GitHub.")
    parser_getpkg.add_argument("-a", "--author", help="Package author.")
    parser_getpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_getpkg.add_argument("-k", "--key", help="Decryption key.")
    parser_getpkg.add_argument("-l", "--location", help="Location of extraction.", default=None)
    parser_mkpkg = subparsers.add_parser("mkpkg", help="Encrypt and upload a package to GitHub.")
    parser_mkpkg.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_mkpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_mkpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
    parser_rmpkg = subparsers.add_parser("rmpkg", help="Delete a package from GitHub.")
    parser_rmpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_rmpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
    parser_createkp = subparsers.add_parser("createkp", help="Create a local Knexyce Package.")
    parser_createkp.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_createkp.add_argument("-k", "--key", help="Encryption key.")
    parser_openkp = subparsers.add_parser("openkp", help="Open a '.kp' file locally.")
    parser_openkp.add_argument("-p", "--package", required=True, help="Package filename.")
    parser_openkp.add_argument("-k", "--key", help="Decryption key.")
    parser_openkp.add_argument("-l", "--location", help="Location of extraction.", default=None)
    args = parser.parse_args()
    if args.command == "getpkg":
        getpkg(args.author, args.package, args.key, args.location)
    elif args.command == "mkpkg":
        mkpkg(args.folder, args.key, args.token)
    elif args.command == "rmpkg":
        rmpkg(args.package, args.token)
    elif args.command == "createkp":
        createkp(args.folder, args.key)
    elif args.command == "openkp":
        openkp(args.package, args.key, args.location)

if __name__ == "__main__":
    main()

# Author: Ayan Alam (Knexyce).
# Note: Knexyce is both a group and individual.
# All rights regarding this software are reserved by Knexyce only.
