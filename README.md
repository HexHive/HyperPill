HyperPill
=========

Building
--------
```bash
CC=clang CXX=clang++ make # for x86_64 hypervisors
ARCH=x86_64 CC=clang CXX=clang++ make # for x86_64 hypervisors
ARCH=aarch64 CC=clang CXX=clang++ make # for aarch64 hypervisors
```

Note: ARCH is unrelated to the host machine architecture.

Using
--------

To fuzz a hypervisor, we first must obtain a snapshot.
To do this, follow the instructions in [hyperpill-snap](hyperpill-snap/)

After collecting the snapshot, the snapshot directory should contain the
following files:
* `dir/mem`
* `dir/regs`
* `dir/vmcs`

where dir can be `kvm`, `hyperv`, `macos`, or whatever you want.

P.S. you may want to run `md5sum dir/mem | cut -d ' ' -f 1 > dir/mem.md5sum` to
make your life easy.

We are using the example directory structure outlined below to keep everything
organized and easy to manage.

``` bash
.
├── HyperPill
├── snapshots/kvm
```

First, enumerate the input-spaces:

```
# Create a working directory
mkdir -p /tmp/fuzz/; cd /tmp/fuzz
export SNAPSHOT_BASE=/path/to/snapshots/kvm
export PROJECT_ROOT=/path/to/HyperPill
KVM=1 FUZZ_ENUM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh
```

After the enumeration stage is complete, we can fuzz the snapshot:

```
mkdir CORPUS
KVM=1 CORPUS_DIR=./CORPUS NSLOTS=$(nproc) $PROJECT_ROOT/scripts/run_hyperpill.sh
```

Additionally, for elf-based hypervisors, it will be convenient to store copies
of the binaries that we expect to be fuzzing for symbolization and breakpointing
purposes. See [hyperpill-snap](hyperpill-snap/) for a description of downloading
the debugging symbols into `dir/symbols`.

To use these symbols, we need to infer the symbol map. To do this:

```
KVM=1 SYMBOLS_DIR=$SNAPSHOT_BASE/symbols $PROJECT_ROOT/scripts/run_hyperpill.sh 2>&1 | grep Symbolization
```

Save the output to `dir/layout`. An example:

```
Symbolization Range: ffffffffc0b3e000 - ffffffffc0b6fa56 size: 31a56 file: dir/symbols/kvm-intel.ko section: .text sh_addr: 0
Symbolization Range: ffffffffb0400000 - ffffffffb12018c2 size: e018c2 file: dir/symbols/vmlinux section: .text sh_addr: ffffffff81000000
Symbolization Range: ffffffffc09dc000 - ffffffffc0a44de3 size: 68de3 file: dir/symbols/kvm.ko section: .text sh_addr: 0
Symbolization Range: 7f4ec7c2e380 - 7f4ec7d81f2d size: 153bad file: dir/symbols/libc.so.6 section: .text sh_addr: 26380
Symbolization Range: 55bc471e6660 - 55bc4813942c size: f52dcc file: dir/symbols/qemu-system-x86_64 section: .text sh_addr: 975660
Symbolization Range: 7f4ec7f05e80 - 7f4ec7f91a1e size: 8bb9e file: dir/symbols/libglib-2.0.so.0 section: .text sh_addr: 1de80
Symbolization Range: 7f4ec88c1530 - 7f4ec88d5c4c size: 1471c file: dir/symbols/libslirp.so.0 section: .text sh_addr: 4530
Symbolization Range: 7ffd204d2000 - 7ffd20927d96 size: 455d96 file: dir/symbols/vmlinux section: .rodata sh_addr: ffffffff82000000
```

Then, remove SYMBOLS_DIR and rerun the fuzzer. Every new PC will be symbolized.

```
KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh
```

We can reproduce a crash:

```
KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-48f2f7
```

Add have more debugging information:

```
KVM=1 FUZZ_DEBUG_DISASM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-48f2f7 2>&1 | tee crash-48f2f7.txt
python3 $PROJECT_ROOT/scripts/symbolize.py $SNAPSHOT_BASE/layout $SNAPSHOT_BASE/symbols/ crash-48f2f7.txt
```

For any bus errors, unlink the shm in /dev/shm or expand the memory.
