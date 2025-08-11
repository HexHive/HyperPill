#!/bin/bash
set -e

poc=$1

if [ -z tests/$poc ]; then
    echo "Please select one poc in tests/. Exiting."
    exit 1
fi

if [[ -z "$KVM" && -z "$HYPERV" && -z "$MACOS" && -z "$SEL4" ]]; then
    echo "None of the environment variables KVM, HYPERV, MACOS, or SEL4 are set. Exiting."
    exit 1
fi

if [ -z $LINK_OBJ_BASE ]; then
    echo "LINK_OBJ_BASE is not set. Exiting."
    exit 1
fi
export LINK_OBJ_PATH="$SNAPSHOT_BASE/symbols/qemu-system-x86_64"
if [ ! -e "$LINK_OBJ_PATH" ]; then
    echo "$LINK_OBJ_PATH does not exist. Exiting."
    exit 1
fi

if [ -z "$ARCH" ]; then
    export ARCH=x86_64
fi

if [ "$ARCH" == "x86_64" ]; then
export ICP_VMCS_LAYOUT_PATH="$PROJECT_ROOT/data/vmcs.layout"
export ICP_VMCS_ADDR=$(cat "$SNAPSHOT_BASE/vmcs")
fi
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
