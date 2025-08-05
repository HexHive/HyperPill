HyperPill
=========

!!! For better communication, please join our [discord](https://discord.gg/dxdvHvrK8D) server. !!!

Building
--------
``` bash
sudo apt-get install libssl-dev libsqlite3-dev \
    bison clang build-essential debuginfod elfutils \
    python3-pip libcapstone4  libcapstone-dev \
    binutils-aarch64-linux-gnu
CC=clang CXX=clang++ make
ARCH=aarch64 CC=clang CXX=clang++ make # for aarch64 hypervisors
```

Note: ARCH is unrelated to the host machine architecture.

Using
--------

Use the following directory structure to keep everything organized and
manageable:

```
.
├── HyperPill
├── snapshots
├── fuzz # working directory
```

To fuzz a hypervisor, first obtain a snapshot following the instructions in
[hyperpill-snap](hyperpill-snap/), or download prebuild snapshots from 
[zenodo](https://zenodo.org/records/15826268).

A valid snapshot snapshot directory must contain the following files:

```
.
└──── dir
   ├── mem
   ├── regs
   └── vmcs 
```

Here `dir` can be `kvm` or any other custom name.

Tip: Run `md5sum mem | cut -d ' ' -f 1 > mem.md5sum` to avoid unnecessary
remapping of the snapshot.


``` bash
export SNAPSHOT_BASE=/path/to/snapshots/kvm
export PROJECT_ROOT=/path/to/HyperPill
cd fuzz
```

For elf-based hypervisors, it is recommended to store relevant binaries in
`dir/symbols` for symbolization and breakpointing.  See
[hyperpill-snap](hyperpill-snap/) for instructions on downloading the debugging
symbols.

To enable automatic symbolization, extract the symbol map:

``` bash
KVM=1 SYMBOLS_DIR=$SNAPSHOT_BASE/symbols $PROJECT_ROOT/scripts/run_hyperpill.sh 2>&1 | grep Symbolization
ARCH=aarch64 KVM=1 SYMBOLS_DIR=$SNAPSHOT_BASE/symbols $PROJECT_ROOT/scripts/run_hyperpill.sh 2>&1 | grep Symbolization
```

Save the output to `dir/layout`. Example output:

```
Symbolization Range: ffffffffc0b3e000 - ffffffffc0b6fa56 size: 31a56 file: dir/symbols/kvm-intel.ko section: .text sh_addr: 0
Symbolization Range: ffffffffb0400000 - ffffffffb12018c2 size: e018c2 file: dir/symbols/vmlinux section: .text sh_addr: ffffffff81000000
Symbolization Range: ffffffffc09dc000 - ffffffffc0a44de3 size: 68de3 file: dir/symbols/kvm.ko section: .text sh_addr: 0
Symbolization Range: 7f4ec7c2e380 - 7f4ec7d81f2d size: 153bad file: dir/symbols/libc.so.6 section: .text sh_addr: 26380
Symbolization Range: 55bc471e6660 - 55bc4813942c size: f52dcc file: dir/symbols/qemu-system-x86_64 section: .text sh_addr: 975660
Symbolization Range: 7f4ec7f05e80 - 7f4ec7f91a1e size: 8bb9e file: dir/symbols/libglib-2.0.so.0 section: .text sh_addr: 1de80
```

Step 1: enumerate input-spaces

``` bash
KVM=1 FUZZ_ENUM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh
ARCH=aarch64 KVM=1 FUZZ_ENUM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh
```

You may skip enumeration by providing a manual QEMU mtree file.

``` bash
export MANUAL_RANGES=$SNAPSHOT_BASE/mtree
export RANGE_REGEX="nvme"
```

Step 2: start fuzzing

``` bash
mkdir CORPUS
KVM=1 CORPUS_DIR=./CORPUS NSLOTS=$(nproc) $PROJECT_ROOT/scripts/run_hyperpill.sh
ARCH=aarch64 KVM=1 CORPUS_DIR=./CORPUS NSLOTS=$(nproc) $PROJECT_ROOT/scripts/run_hyperpill.sh
```

If `dir/layout` is valid, new PCs will be automatically symbolized. Crash files
will be saved to the working directory, e.g., `crash-04975a...`.

Step 3: reproduce a crash

``` bash
KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-04975a...
KVM=1 ARCH=aarch64 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-48f2f7
```

Step 4: debug a crash

To get more context with symbols:

``` bash
KVM=1 FUZZ_DEBUG_DISASM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-xxx 2>&1 | tee crash-xxx.txt
python3 $PROJECT_ROOT/scripts/symbolize.py $SNAPSHOT_BASE/layout $SNAPSHOT_BASE/symbols/ crash-xxx.txt
```

To debug interactively using GDB:

``` bash
# Terminal 1
GDB=1 KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-xxx
# or
VERBOSE=1 GDB=1 KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-xxx

# Terminal 2
gdb -ex "set architecture i386:x86-64"
# if you are using gef
# $ (gdb) arch set X86_64
# for debugging HyperPill's gdbstub
# $ (gdb) set debug remote on
# $ (gdb) set remotetimeout 99999
$ (gdb) target remote:1234
```

Tip: Export LINK_OBJ_BASE to rebase the object being debugged

Tip: If HyperPill is running on a remote server, forward the debug port to your
local machine using SSH:

``` bash
ssh -N -L 1234:localhost:1234 user@server
```

Tip: When using the Ghidra debugger (e.g., to debug non-ELF binaries), configure
and launch a GDB Remote session by specifying the input file, target port, GDB
command (or a custom GDB wrapper script), and architecture (e.g., i386:x86-64).

For troubleshooting and FAQs, refer to the [Common Questions
page](https://github.com/HexHive/HyperPill/wiki/Common-Questions).

Collecting source-based coverage
--------

Step 1: compile instrumented QEMU to run L2 VM

``` bash
CC=clang CXX=clang++ \
    ../configure --target-list=x86_64-softmmu --enable-slirp \
    --extra-cflags="-fprofile-instr-generate -fcoverage-mapping"
ninja
```

Step 2: retake the snapshot and reinfer the symbol map

Step 3: determine `LINK_OBJ_BASE`

For a symbolization line like

```
Symbolization Range: 55bc471e6660 - ... file: ...qemu-system-x86_64 ....text sh_addr: 975660
```

Calculate:

```
LINK_OBJ_BASE = hex(0x55bc471e6660-0x975660) = 0x55bc46871000
```

Or simply run:

``` bash
$PROJECT_ROOT/scripts/cal_link_obj_base.sh
```

Step 4: run HyperPill with coverage

``` bash
export LINK_OBJ_BASE=0x55bc46871000
KVM=1 NSLOTS=1 $PROJECT_ROOT/scripts/run_hyperpill2.sh
```

Tip: NSLOTS=1 is required for generating `profraw` files.

Step 5: collect coverage files

After running for some time (> 300s), you should see `profraw` files in working
directory:

```
[L0] $ ls *profraw
172037-1740394346.profraw
```

Step 6: process and visualize coverage

```
[L0] $ scp -P 2222 172037-1740394346.profraw root@localhost:/tmp/
[L0] $ ssh -p 2222 root@localhost llvm-profdata-14 merge -output=/tmp/default.profdata /tmp/172037-1740394346.profraw
[L0] $ ssh -p 2222 root@localhost llvm-cov-14 show --format=html /root/qemu-8.0.0/build/qemu-system-x86_64 -instr-profile=/tmp/default.profdata -output-dir=/tmp/cov
[L0] $ scp -r -P 2222 root@localhost:/tmp/cov ./
```
