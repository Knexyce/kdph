#!/usr/bin/env bash
# Optical Package Manager

# More user friendly frontend for KDPH.
# System level package manager with dependency resolution, package building, and configuring by using a configuration file ("optcfg.py") in packages.
# Powered by KDPH engine and retains the same features.

curl https://raw.githubusercontent.com/Knexyce/kdph/main/kdph.py -o /tmp/kdph.py
python3 /tmp/kdph.py getpkg -a k-auto -p optical -k kp
rm /tmp/kdph.py
cd optical
./setup.sh
cd ~

echo "Optical has been installed."

# Author: Ayan Alam (Knexyce).
# All rights regarding this software are reserved by Knexyce only.
