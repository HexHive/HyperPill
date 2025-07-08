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

def generate_master_run_script(base_dir, output_script="run.sh"):
    """
    Scans for all fuzz-* directories and writes commands to run their run.sh scripts into a master script.
    """
    lines = [
        "#!/bin/bash\n\n",
    ]

    for entry in sorted(os.listdir(base_dir)):
        entry_path = os.path.join(base_dir, entry)
        run_script = os.path.join(entry_path, "run.sh")
        if entry.startswith("fuzz-") and os.path.isdir(entry_path) and os.path.isfile(run_script):
            lines.append(f"echo '[+] Running {entry}/run.sh'\n")
            lines.append(f"pushd {entry} > /dev/null\n")
            lines.append(f"./run.sh &\n")
            lines.append(f"popd > /dev/null\n\n")

    output_path = os.path.join(base_dir, output_script)
    with open(output_path, "w") as f:
        f.writelines(lines)

    os.chmod(output_path, 0o755)
    print(f"[+] Created run script at: {output_path}")

def create_fuzzing_config(project_root, snapshot_base, target, config_path):
    """
    Creates a fuzzing work directory and corresponding environment script.
    """
    work_dir = os.path.join(os.path.dirname(project_root), f"fuzz-{target}")
    os.makedirs(work_dir, exist_ok=True)

    env_script = os.path.join(work_dir, "env.sh")
    with open(env_script, "w") as f:
        f.write(f"#!/bin/bash\n\n")
        f.write(f"export PROJECT_ROOT={project_root}\n")
        f.write(f"export SNAPSHOT_BASE={snapshot_base}\n")
        f.write(f"export MANUAL_RANGES=$SNAPSHOT_BASE/mtree\n")
        f.write(f"source {config_path}\n")

    run_script = os.path.join(work_dir, "run.sh")
    with open(run_script, "w") as f:
        f.write(f"#!/bin/bash\n\n")
        f.write(f"source env.sh\n")
        f.write(f"mkdir CORPUS\n")
        f.write(f"KVM=1 CORPUS_DIR=./CORPUS NSLOTS=4 $PROJECT_ROOT/scripts/run_hyperpill.sh\n")
    os.system(f"chmod +x {run_script}")

    print(f"[+] Created run script at: {run_script}")

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
    generate_master_run_script(os.path.dirname(project_root))

if __name__ == "__main__":
    main()
