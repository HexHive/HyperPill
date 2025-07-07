HyperPill
=========

!!! For better communication, please join our [discord](https://discord.gg/dxdvHvrK8D) server. !!!

Building
--------
CC=clang CXX=clang++ make

Using
--------

We are using the example directory structure outlined below to keep everything
organized and easy to manage.

``` bash
.
├── HyperPill
├── snapshots
├── fuzz # working directory
```

To fuzz a hypervisor, we first must obtain a snapshot.
To do this, follow the instructions in [hyperpill-snap](hyperpill-snap/).

After collecting the snapshot, the snapshot directory should contain the
following files:
* `dir/mem`
* `dir/regs`
* `dir/vmcs`

where dir can be `kvm`, or whatever you want.

P.S. run `md5sum dir/mem | cut -d ' ' -f 1 > dir/mem.md5sum` to avoid remapping
the snapshot.

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
```

First, enumerate the input-spaces,

```
# In the working directory
export SNAPSHOT_BASE=/path/to/snapshots/kvm
export PROJECT_ROOT=/path/to/HyperPill
KVM=1 FUZZ_ENUM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh
```

We can also skip the enumerating stage with manual ranges. A QEMU-like mtree
file must be obtained or constructed.

```
export MANUAL_RANGES=$SNAPSHOT_BASE/mtree
export RANGE_REGEX="nvme"
```

After the enumeration stage is complete, we can fuzz the snapshot:

```
mkdir CORPUS
KVM=1 CORPUS_DIR=./CORPUS NSLOTS=$(nproc) $PROJECT_ROOT/scripts/run_hyperpill.sh
```

If `dir/layout` is valid, every new PC will be symbolized.

A crash file will be dumped into the working directory, e.g.,
`crash-04975a94754989e01ff516404dbef455ec6ac613`.

We can reproduce the crash:

```
KVM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-xxx
```

To understand any crash (either in HyperPill or in the target hypervisor), we
can enable more debugging information.

```
KVM=1 FUZZ_DEBUG_DISASM=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-xxx 2>&1 | tee crash-xxx.txt
python3 $PROJECT_ROOT/scripts/symbolize.py $SNAPSHOT_BASE/layout $SNAPSHOT_BASE/symbols/ crash-xxx.txt
```

For common errors when using HyperPill, see [this
page](https://github.com/HexHive/HyperPill/issues/26).

## Collecting source-based coverage

First, config the QEMU to run L2 VM and compile.

```
CC=clang CXX=clang++ \
../configure --target-list=x86_64-softmmu --enable-slirp \
--extra-cflags="-fprofile-instr-generate -fcoverage-mapping"
ninja
```

Second, retake the snapshot and reinfer the symbol map.

Third, set LINK_OBJ_BASE and run `KVM=1 NSLOTS=1
$PROJECT_ROOT/scripts/run_hyperpill2.sh`. Here NSLOTS is needed otherwise clang
profraw file will not be generated.

How to calculate LINK_OBJ_BASE? Suppose we have the symbolization range of
qemu-system-x86_64 below,

```
Symbolization Range: 55bc471e6660 - ... file: ...qemu-system-x86_64 ....text sh_addr: 975660
```

LINK_OBJ_BASE is hex(0x55bc471e6660-0x975660), which is 0x55bc46871000.

Or run `$PROJECT_ROOT/scripts/cal_link_obj_base.sh`.

After at least 300s, there will be clang profraw files under the fuzz working
directory. For example:

```
[L0] $ ls *profraw
172037-1740394346.profraw
```

Finally, collect coverage results within L1
```
[L0] $ scp -P 2222 172037-1740394346.profraw root@localhost:/tmp/
[L0] $ ssh -p 2222 root@localhost llvm-profdata-14 merge -output=/tmp/default.profdata /tmp/172037-1740394346.profraw
[L0] $ ssh -p 2222 root@localhost llvm-cov-14 show --format=html /root/qemu-8.0.0/build/qemu-system-x86_64 -instr-profile=/tmp/default.profdata -output-dir=/tmp/cov
[L0] $ scp -r -P 2222 root@localhost:/tmp/cov ./
```
