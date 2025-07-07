#!/usr/bin/env python3
#
# This script creates work directories to fuzz QEMU/KVM using HyperPill.
#
# A snapshot must be prepared beforehand.
#
# Usage: python3 create_qemu_km.py path/to/snapshots/kvm
#
# Polished by ChatGPT.
#

import os
import sys

def create_fuzzing_config(project_root, snapshot_base, target, config_path):
    """
    Creates a fuzzing work directory and corresponding environment script.
    """
    work_dir = os.path.join(os.path.dirname(project_root), f"fuzz-{target}")
    os.makedirs(work_dir, exist_ok=True)

    env_script = os.path.join(work_dir, "env.sh")
    with open(env_script, "w") as f:
        f.write(f"export PROJECT_ROOT={project_root}\n")
        f.write(f"export SNAPSHOT_BASE={snapshot_base}\n")
        f.write(f"export MANUAL_RANGES=$SNAPSHOT_BASE/mtree\n")
        f.write(f"source {config_path}\n")

    print(f"[+] Created environment script at: {env_script}")

def create_all_fuzzing_configs(project_root, snapshot_base):
    """
    Iterates over all config scripts in the 'configs' directory to generate fuzzing environments.
    """
    config_dir = os.path.join(project_root, "configs")
    if not os.path.isdir(config_dir):
        print(f"Error: Config directory not found at {config_dir}")
        sys.exit(1)

    for filename in os.listdir(config_dir):
        if not filename.endswith(".sh"):
            continue
        try:
            target = filename.rsplit("_", 1)[1].removesuffix(".sh")
        except IndexError:
            print(f"Warning: Skipping unrecognized config filename: {filename}")
            continue

        config_path = os.path.join(config_dir, filename)
        create_fuzzing_config(project_root, snapshot_base, target, config_path)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} path/to/snapshots/kvm")
        sys.exit(1)

    snapshot_base = os.path.abspath(sys.argv[1])
    project_root = os.path.abspath(os.getcwd())

    create_all_fuzzing_configs(project_root, snapshot_base)

if __name__ == "__main__":
    main()
