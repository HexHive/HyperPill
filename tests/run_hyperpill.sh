#!/bin/bash
set -e

poc=$1

if [ -z tests/$poc ]; then
    echo "Please select one poc in tests/. Exiting."
    exit 1
fi

if [[ -z "$KVM" && -z "$HYPERV" && -z "$MACOS" ]]; then
    echo "None of the environment variables KVM, HYPERV, or MACOS are set. Exiting."
    exit 1
fi
export NOCOV=1

export ICP_VMCS_LAYOUT_PATH="$PROJECT_ROOT/data/vmcs.layout"
export ICP_VMCS_ADDR=$(cat "$SNAPSHOT_BASE/vmcs")
export SYMBOL_MAPPING="$SNAPSHOT_BASE/layout"
export ICP_MEM_PATH="$SNAPSHOT_BASE/mem"
if [ -e "$SNAPSHOT_BASE/mem.md5sum" ]; then
    export ICP_MEM_MD5SUM=$(cat "$SNAPSHOT_BASE/mem.md5sum")
fi
export ICP_REGS_PATH="$SNAPSHOT_BASE/regs"
export ICP_DB_PATH="$SNAPSHOT_BASE/snap.sqlite"

cp "$PROJECT_ROOT/tests/$poc" .
# gdb --args \
./$poc
