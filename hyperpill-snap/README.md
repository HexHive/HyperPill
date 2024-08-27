# HyperPill Hypervisor Fuzzer

## Instructions
Here we describe how to collect a snapshot of a hypervisor.

### HP-Snap
First, fetch a recent version of the Linux Kernel (we tested 6.0 on debian) and
apply our KVM-patch.
```bash
[L0] $ wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.0.tar.gz
[L0] $ tar -xvf linux-6.0.tar.gz
[L0] $ cd  kernel/
[L0] $ patch -p1 < /path/to/hp-snap/hp-snap-kvm.patch
[L0] $ make defconfig
[L0] $ grep .config CONFIG_KVM
# Verify that CONFIG_KVM_INTEL is set to =m
[L0] $ make M=./arch/x86/kvm/
# Ensure that you are not currently running any virtual machines
[L0] $ rmmod kvm_intel
[L0] $ sudo insmod arch/x86/kvm/kvm-intel.ko dump_invalid_vmcs=1 nested=1


[L0] $ cd ..
# Install QEMU Dependencies: https://wiki.qemu.org/Hosts/Linux
[L0] wget https://download.qemu.org/qemu-8.0.0.tar.bz2
[L0] tar -xvf qemu-8.0.0.tar.bz2
[L0] cd qemu
[L0] $ patch -p1 < /path/to/hp-snap/hp-snap-qemu.patch
[L0] $ mkdir build; cd build;
[L0] $ ../configure --target-list=x86_64-softmmu
[L0] $ ninja -j$(nproc)

# Now use the build qemu to create a single-CPU VM [L1] and install a
hypervisor within it. Configure a linux VM [L2] within the hypervisor.

# Example command to launch a debian VM for snapshotting QEMU-KVM:
./qemu-system-x86_64 -machine q35 -accel kvm -m 8G \
    -cpu host,-pku,-xsaves,-kvmclock,-kvm-pv-unhalt \
    -netdev user,id=u1,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=u1 -smp 1 -serial stdio \
    -hda debian-13-nocloud-amd64-daily-20240606-1770.qcow2 \
    -monitor telnet:127.0.0.1:55556,server,nowait

# In L2, we use the following tool to trigger a snapshot:
[L2] $ cat > snap.c << EOF
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t size = 0x100000; // 4G
    int fd = open("/dev/random", O_RDONLY);
    int i =0;
    void *bloat = -1;
    if(!fork()) {
        mlockall( MCL_CURRENT | MCL_FUTURE );

        while(bloat !=  NULL){
            bloat = malloc(size);
            if(bloat == NULL) {
                printf("MMAP FAILED\n");
            } else {
                memset(bloat, 1, size);
                printf("BLOAT %p\n", bloat);
            }
        }
        exit(0);
    } else {
            wait(NULL);
            uint64_t rax;;
            __asm__ __volatile__("mov $0xdeadbeef, %rax\n");
            asm volatile("vmcall");
    }
}
EOF

[L2] $ gcc snap.c -o snap
[L2] $ ./snap

# Now in L0, collect the snapshot data. (All remaining commands executed on L0)
[L0] mkdir /path/to/snapshot
# Attach to qemu monitor:
[L0] $ telnet localhost 55556
[L0 qemu-monitor] dump-guest-memory /path/to/snapshot/mem
[L0 qemu-monitor] info registers
# Copy the output of the above command to /path/to/snapshot/regs
# Exit out of the qemu monitor
[L0 qemu-monitor] exit
# Copy the VMCS address
[L0] sudo dmesg | grep "VMCS.*last" | cut -f2 -d"(" | cut -f1 -d ")" > /path/to/snapshot/vmcs
```
The snapshot should now be ready for emulation/fuzzing.
