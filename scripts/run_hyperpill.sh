#!/bin/bash
set -e

if [ -z "$NSLOTS" ]; then
    export LIBFUZZER_ARGS="$LIBFUZZER_ARGS"
else
export LIBFUZZER_ARGS="-jobs=$NSLOTS -workers=$NSLOTS $LIBFUZZER_ARGS"
fi

export ASAN_OPTIONS=use_sigaltstack=false
LIBFUZZER_FLAGS="-max_len=8192 -rss_limit_mb=-1 -detect_leaks=0 -use_value_profile=1 -reload=60 \
    -dict=$PROJECT_ROOT/data/dict \
    $LIBFUZZER_ARGS $CORPUS_DIR
    "
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

cp "$PROJECT_ROOT/fuzz" .
./fuzz $LIBFUZZER_FLAGS
