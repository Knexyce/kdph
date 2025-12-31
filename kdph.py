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

import os
import sys
import shutil
import subprocess
import getpass
import argparse
import base64
import hashlib
import json
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path
from fnmatch import fnmatch
from datetime import datetime, timezone

try:
    import cryptography
    import argon2
    import requests
    from github import Github, Auth
except Exception:
    install_pip()
    upgrade_pip()
    pip_install("cryptography")
    pip_install("argon2-cffi")
    pip_install("requests")
    pip_install("PyGithub")
    os.execv(sys.executable, [sys.executable] + sys.argv)

def encrypt_file(input_file: str, output_file: str, password, layers: int = 1):
    import os, shutil, tempfile, struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
    CHUNK_SIZE = 64 * 1024 * 1024
    KEY_ROTATION_SIZE = 12 * 1024**3
    SALT_SIZE = 32
    NONCE_SIZE = 12
    ARGON2_TIME_COST = 32
    ARGON2_MEMORY_COST = 768 * 1024
    ARGON2_PARALLELISM = 8
    KEY_LEN = 32
    def derive_key(password: bytes, salt: bytes) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LEN,
            type=Type.ID
        )
    def safe_replace(src, dst):
        dst_tmp = dst + ".tmp"
        shutil.copy2(src, dst_tmp)
        with open(dst_tmp, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        os.replace(dst_tmp, dst)
        os.remove(src)
    if input_file == output_file:
        raise ValueError()
    current_input = input_file
    for layer in range(layers):
        temp_out = tempfile.NamedTemporaryFile(delete=False)
        temp_out_name = temp_out.name
        temp_out.close()
        temp_meta = tempfile.NamedTemporaryFile(delete=False)
        temp_meta_name = temp_meta.name
        temp_meta.close()
        total_processed = 0
        key = None
        aesgcm = None
        salt = None
        try:
            with open(current_input, 'rb') as f, open(temp_out_name, 'wb') as out_f, open(temp_meta_name, 'wb') as meta_f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    while chunk:
                        remaining_to_rotation = KEY_ROTATION_SIZE - (total_processed % KEY_ROTATION_SIZE)
                        if len(chunk) > remaining_to_rotation:
                            to_encrypt = chunk[:remaining_to_rotation]
                            chunk = chunk[remaining_to_rotation:]
                        else:
                            to_encrypt = chunk
                            chunk = b''
                        if total_processed % KEY_ROTATION_SIZE == 0:
                            salt = os.urandom(SALT_SIZE)
                            key = derive_key(password, salt)
                            aesgcm = AESGCM(key)
                        nonce = os.urandom(NONCE_SIZE)
                        metadata_entry = salt + nonce + struct.pack(">Q", len(to_encrypt))
                        enc_chunk = aesgcm.encrypt(nonce, to_encrypt, metadata_entry)
                        meta_f.write(metadata_entry)
                        out_f.write(enc_chunk)
                        total_processed += len(to_encrypt)
            final_file = tempfile.NamedTemporaryFile(delete=False)
            final_file_name = final_file.name
            final_file.close()
            metadata_len = os.path.getsize(temp_meta_name)
            with open(final_file_name, 'wb') as f_out, open(temp_meta_name, 'rb') as meta_f, open(temp_out_name, 'rb') as enc_f:
                f_out.write(struct.pack(">Q", metadata_len))
                shutil.copyfileobj(meta_f, f_out)
                shutil.copyfileobj(enc_f, f_out)
        finally:
            os.remove(temp_out_name)
            os.remove(temp_meta_name)
            if current_input != input_file:
                os.remove(current_input)
        current_input = final_file_name
    safe_replace(current_input, output_file)

def decrypt_file(input_file: str, output_file: str, password, layers: int = 1):
    import os, shutil, tempfile, struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
    KEY_ROTATION_SIZE = 12 * 1024**3
    SALT_SIZE = 32
    NONCE_SIZE = 12
    ARGON2_TIME_COST = 32
    ARGON2_MEMORY_COST = 768 * 1024
    ARGON2_PARALLELISM = 8
    KEY_LEN = 32
    def derive_key(password: bytes, salt: bytes) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LEN,
            type=Type.ID
        )
    def safe_replace(src, dst):
        dst_tmp = dst + ".tmp"
        shutil.copy2(src, dst_tmp)
        with open(dst_tmp, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        os.replace(dst_tmp, dst)
        os.remove(src)
    if input_file == output_file:
        raise ValueError()
    current_input = input_file
    temp_files = []
    for layer in range(layers):
        temp_out = tempfile.NamedTemporaryFile(delete=False)
        temp_out_name = temp_out.name
        temp_out.close()
        temp_files.append(temp_out_name)
        with open(current_input, 'rb') as f:
            metadata_len_bytes = f.read(8)
            metadata_len = struct.unpack(">Q", metadata_len_bytes)[0]
            metadata_start = f.tell()
            ciphertext_start = metadata_start + metadata_len
        total_processed = 0
        key = None
        aesgcm = None
        with open(current_input, 'rb') as f, open(temp_out_name, 'wb') as out_f:
            f.seek(metadata_start)
            while f.tell() < ciphertext_start:
                salt = f.read(SALT_SIZE)
                nonce = f.read(NONCE_SIZE)
                length = struct.unpack(">Q", f.read(8))[0]
                if total_processed % KEY_ROTATION_SIZE == 0:
                    key = derive_key(password, salt)
                    aesgcm = AESGCM(key)
                metadata_entry = salt + nonce + struct.pack(">Q", length)
                enc_chunk = f.read(length + 16)
                decrypted_chunk = aesgcm.decrypt(nonce, enc_chunk, metadata_entry)
                out_f.write(decrypted_chunk)
                total_processed += len(decrypted_chunk)
        if current_input != input_file:
            os.remove(current_input)
        current_input = temp_out_name
    for temp_file in temp_files[:-1]:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    safe_replace(current_input, output_file)

def archive_folder(target_folder: str, output_archive: str, ignore=None):
    target_path = Path(target_folder).resolve()
    ignore_set = {Path(p).as_posix() for p in ignore} if ignore else set()
    with ZipFile(output_archive, "w", ZIP_DEFLATED) as z:
        for p in target_path.rglob("*"):
            rel_path = p.relative_to(target_path).as_posix()
            if any(fnmatch(rel_path, pattern) for pattern in ignore_set):
                continue
            if p.is_dir() and not any(p.iterdir()):
                z.write(p, arcname=f"{target_path.name}/{rel_path}/")
            elif p.is_file():
                z.write(p, arcname=f"{target_path.name}/{rel_path}")

def extract_archive(archive_file: str, extraction_path: str):
    output = Path(extraction_path).parent
    with ZipFile(archive_file, "r") as z:
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
            content_str = f.read()
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

def cluster_file(target_file, output_folder="cluster", chunk_size=16*1024*1024):
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

def kpinfo(folder, topic, output=False):
    folder_path = Path(folder).resolve()
    metadata_path = folder_path / "kpcore" / "metadata.json"
    if not metadata_path.exists():
        raise FileNotFoundError()
    with open(metadata_path) as f:
        metadata = json.load(f)
    value = metadata.get(topic)
    if output:
        print(value)
    return value

def createkp(folder, location=None, key=None):
    folder_path = Path(folder).resolve()
    folder_name = folder_path.name
    kp_file = f"{folder_name}.kp"
    if key is None:
        key = getpass.getpass(f"Enter a passphrase to encrypt '{folder_name}'. ")
    if location is None:
        location = Path.cwd()
    kpcore = folder_path / "kpcore"
    kpcore.mkdir(exist_ok=True)
    build_path = kpcore / "build.py"
    pkgdeps_path = kpcore / "pkgdeps.json"
    importable_path = kpcore / "__init__.py"
    metadata_path = kpcore / "metadata.json"
    ignore_path = kpcore / "ignore.txt"
    kdph_copy = kpcore / "kdph.py"
    info_path = kpcore / "INFO.md"
    if not build_path.exists():
        with open(build_path, "w") as f:
            f.write("""# Package Builder

# "build.py" identifies a folder as a Knexyce Package (KP) and is auto-generated if missing.
# Replace these comments with configuration and package-building code.
""")
    if not pkgdeps_path.exists():
        with open(pkgdeps_path, "w") as f:
            f.write("{}\n")
    if not importable_path.exists():
        with open(importable_path, "w") as f:
            f.write("# KPCore directory.\n")
    if not ignore_path.exists():
        with open(ignore_path, "w") as f:
            f.write("""# Lines of paths that get ignored during packaging.
# Use relative POSIX-style paths only.
""")
    if not info_path.exists():
        with open(info_path, "w") as f:
            f.write("""# KPCore Information

This folder contains the core files used by Knexyce Package (KP) system.

- **build.py**: Executed when opening the package to build and configure it.
- **pkgdeps.json**: Lists package dependencies to be installed.

- **Example**
```
{
  "githubpkg": {
    "author": "github_user",
    "location": null
  },
  "localpkg": {
    "filepath": "local_packages/localpkg.kp",
    "key": "passphrase",
    "location": "deps/localpkg"
  }
}
```

- **metadata.json**: Stores package metadata for KDPH to query.
- **ignore.txt**: Paths to exclude from packaging.
- **kdph.py**: Copy of the KDPH script used to create this package.
- **INFO.md**: This informational file.
""")
    if not metadata_path.exists():
        metadata = {
            "name": folder_name,
            "version": "0.0.1",
            "author": getpass.getuser(),
            "description": "KPCore-powered package.",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_built": None
        }
    else:
        with open(metadata_path) as f:
            metadata = json.load(f)
        major, minor, patch = [int(x) for x in metadata.get("version", "0.0.1").split(".")]
        patch += 1
        if patch > 9:
            patch = 0
            minor += 1
        if minor > 9:
            minor = 0
            major += 1
        metadata["version"] = f"{major}.{minor}.{patch}"
    metadata["last_built"] = datetime.now(timezone.utc).isoformat()
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    with open(Path(__file__).resolve(), "rb") as f:
        with open(kdph_copy, "wb") as o:
            o.write(f.read())
    ignore = []
    with open(ignore_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ignore.append(line)
    archive_file = f"{folder_name}.zip"
    archive_folder(str(folder_path), archive_file, ignore=ignore)
    output_path = Path(location) / kp_file
    encrypt_file(archive_file, str(output_path), key)
    os.remove(archive_file)
    with open(kdph_copy, "rb") as f:
        sha = hashlib.sha256(f.read()).digest()
    with open(output_path, "ab") as f:
        f.write(sha)

def extractkp(package, location=None, key=None):
    if key is None:
        key = getpass.getpass(f"Enter the passphrase to decrypt '{package}'. ")
    package = str(Path(package).resolve())
    package_name = Path(package).stem
    if location:
        location = str((Path(location) / package_name).resolve())
    else:
        location = str(Path(package_name).resolve())
    raw_package = f"{package_name}.enc"
    temp_decrypted = f"{package_name}.zip"
    with open(package, "rb") as f:
        f.seek(-32, os.SEEK_END)
        sha_stored = f.read()
    kdph_running = Path(__file__).resolve()
    with open(kdph_running, "rb") as f:
        sha_actual = hashlib.sha256(f.read()).digest()
    if sha_actual != sha_stored:
        raise ValueError()
    with open(package, "rb") as f:
        content = f.read()[:-32]
    with open(raw_package, "wb") as f:
        f.write(content)
    decrypt_file(raw_package, temp_decrypted, key)
    extract_archive(temp_decrypted, location)
    os.remove(temp_decrypted)
    os.remove(raw_package)
    kpcore_path = Path(location) / "kpcore"
    pkgdeps_path = kpcore_path / "pkgdeps.json"
    if pkgdeps_path.exists():
        with open(pkgdeps_path) as f:
            deps = json.load(f)
        package_root = Path(location)
        for dep, meta in deps.items():
            dep_location = meta.get("location")
            dep_location = package_root if dep_location is None else (package_root / dep_location).resolve()
            if "author" in meta:
                getpkg(meta["author"], dep, meta.get("key"), dep_location)
            elif "filepath" in meta:
                extractkp(str(Path(meta["filepath"]).resolve()), meta.get("key"), dep_location)
    build_path = Path(location) / "kpcore" / "build.py"
    subprocess.run([sys.executable, str(build_path)], cwd=str(location), check=True)

def rmpkg(package, token=None):
    if token is None:
        token = getpass.getpass("Enter a 'delete_repo' scope GitHub PAT. ")
    client = Github(auth=Auth.Token(token))
    author = client.get_user()
    package = author.get_repo(package)
    package.delete()

def mkpkg(folder, key=None, token=None):
    folder_path = os.path.abspath(os.path.normpath(folder))
    folder_name = os.path.basename(folder_path.rstrip(os.sep))
    if token is None:
        token = getpass.getpass("Enter a 'delete_repo' and 'repo' scope GitHub PAT. ")
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

Ensure `kdph.py` is installed before installing this package.
"""
    with open("README.md", "w") as f:
        f.write(package_info)
    createkp(folder, None, key)
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

def getpkg(author, package, location=None, key=None):
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
    extractkp(package_enc, location, key)
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
    parser_getpkg.add_argument("-l", "--location", help="Location of extraction.", default=None)
    parser_getpkg.add_argument("-k", "--key", help="Decryption key.")
    parser_mkpkg = subparsers.add_parser("mkpkg", help="Encrypt and upload a package to GitHub.")
    parser_mkpkg.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_mkpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_mkpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
    parser_rmpkg = subparsers.add_parser("rmpkg", help="Delete a package from GitHub.")
    parser_rmpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_rmpkg.add_argument("-t", "--token", help="GitHub Personal Access Token.", default=None)
    parser_kpinfo = subparsers.add_parser("kpinfo", help="Query metadata from a decrypted KP folder.")
    parser_kpinfo.add_argument("-f", "--folder", required=True, help="Package folder to query.")
    parser_kpinfo.add_argument("-t", "--topic", required=True, help="Metadata topic to retrieve.")
    parser_createkp = subparsers.add_parser("createkp", help="Create a local Knexyce Package.")
    parser_createkp.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_createkp.add_argument("-l", "--location", help="Output package location.", default=None)
    parser_createkp.add_argument("-k", "--key", help="Encryption key.")
    parser_extractkp = subparsers.add_parser("extractkp", help="Open a '.kp' file locally.")
    parser_extractkp.add_argument("-p", "--package", required=True, help="Package filename.")
    parser_extractkp.add_argument("-l", "--location", help="Location of extraction.", default=None)
    parser_extractkp.add_argument("-k", "--key", help="Decryption key.")
    args = parser.parse_args()
    if args.command == "getpkg":
        getpkg(args.author, args.package, args.location, args.key)
    elif args.command == "mkpkg":
        mkpkg(args.folder, args.key, args.token)
    elif args.command == "rmpkg":
        rmpkg(args.package, args.token)
    elif args.command == "kpinfo":
        kpinfo(args.folder, args.topic, output=True)
    elif args.command == "createkp":
        createkp(args.folder, args.location, args.key)
    elif args.command == "extractkp":
        extractkp(args.package, args.location, args.key)

if __name__ == "__main__":
    main()

# Author: Ayan Alam (Knexyce).
# Note: Knexyce is both a group and individual.
# All rights regarding this software are reserved by Knexyce only.
