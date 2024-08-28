HyperPill
=========

Building
--------
CC=clang CXX=clang++ make

Using
--------

To fuzz a hypervisor, we first must obtain a snapshot.
To do this, follow the instructions in [hyperpill-snap](hyperpill-snap/)

After collecting the snapshot, the snapshot directory should contain the
following files:
* `dir/mem`
* `dir/layout`
* `dir/vmcs`

where dir can be `kvm`, `hyperv`, or `macos`.

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
purposes. These can be copied from the hypervisor VM:

E.g.:
```bash
# ls dir/symbols/
kvm-intel.ko
kvm.ko
libc.so.6
libglib-2.0.so.0
libslirp.so.0
qemu-system-x86_64
vmlinux
```

To use these symbols, we need to infer the symbol map. To do this:

```
KVM=1 SYMBOLS_DIR=$SNAPSHOT_BASE/symbols $PROJECT_ROOT/scripts/run_hyperpill.sh
```
