# HP-Snap Instructions

Here we describe how to collect a snapshot of a hypervisor.

We are using the example directory structure outlined below to keep everything
organized and easy to manage.

``` bash
.
├── HyperPill
├── snapshots
├── linux-6.0.tar.gz
├── qemu-8.0.0.tar.bz2
```

Our snapshots consist of 3 components:
- L1 Memory
- L1 Registers
- Location of the VMCS12 in L1's Physical Memory

A few requirements:

- We need to make the snapshot as L2 is exiting into L1. (L1 returns from a
vmresume instruction). To do this we run a custom kvm.ko on L0 which detects a
special hypercall (0xdeadbeef) and pauses L1 for us to make the snapshot.

- We want to make sure as much of L2's physical memory is in the resident set as
possible. To do this, we mmap and fill as much memory as possible on L2 until
the kernel kills our process for oom reasons. Only then we call our hypercall.

- By default, qemu doesn't dump all the registers we need, so we need to apply
qemu.patch to get the rest.

So the typical workflow for making a snapshot is:

- Setup L0 KVM: Load the modified kvm.ko into the L0 kernel.
- Run L1 and L2 VMs: Start the target hypervisor as L1 using qemu and start a VM
in the target hypervisor as L2.
- Take the snapshot: In L2, run snap.c, which will try to use as much memory as
possible, before calling the hypercall. At this point the L1 and L2 VMs should
be frozen. In the qemu monitor on L0, run info registers and save the output to
a file (L1 Registers), run dump-guest-memory /path/to/memory-dump (L1 Memory),
and on L0, get the VMCS address by running "sudo dmesg".

## Setup L0 KVM

First, fetch a recent version of the Linux Kernel (we tested 6.0 on debian) and
apply our KVM-patch, or compile the Linux kernel from source (we tested 6.0 on
ubuntu 22.04).

```bash
# Fetch a recent version of the Linux kernel and apply our KVM-patch
[L0] $ wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.0.tar.gz
[L0] $ tar -xvf linux-6.0.tar.gz
[L0] $ cd linux-6.0
[L0] $ patch -p1 < /path/to/HyperPill/hyperpill-snap/hp-snap-kvm.patch
[L0] $ make defconfig
[L0] $ grep .config CONFIG_KVM
# Verify that CONFIG_KVM_INTEL is set to =m
[L0] $ make M=./arch/x86/kvm/
# Ensure that you are not currently running any virtual machines
[L0] $ rmmod kvm_intel
[L0] $ sudo insmod arch/x86/kvm/kvm-intel.ko dump_invalid_vmcs=1 nested=1
```

``` bash
# Compile the Linux Kernel from source
[L0] $ sudo apt install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev fakeroot
[L0] $ sudo apt install -y dwarves
[L0] $ wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.0.tar.gz
[L0] $ tar xf linux-6.0.tar.gz
[L0] $ cd linux-6.0
[L0] $ patch -p 1 < /path/to/HyperPill/hyperpill-snap/hp-snap-kvm.patch
[L0] $ make localmodconfig # just hit enter each time without typing an answer
[L0] $ scripts/config --disable SYSTEM_TRUSTED_KEYS
[L0] $ scripts/config --disable SYSTEM_REVOCATION_KEYS
[L0] $ scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
[L0] $ scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
[L0] $ fakeroot make # it takes time
[L0] $ sudo make modules_install
[L0] $ sudo make install
[L0] $ sudo update-grub

[L0] $ sudo reboot # choose linux-6.0 when booting

[L0] $ cd linux-6.0
[L0] $ sudo rmmod kvm_intel
[L0] $ sudo insmod arch/x86/kvm/kvm-intel.ko dump_invalid_vmcs=1 nested=1
```

## Run L1 and L2 VMs

``` bash
# Install QEMU Dependencies: https://wiki.qemu.org/Hosts/Linux
[L0] $ sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build
[L0] $ sudo apt-get install python3 python3-pip python3-venv # Recent QEMU may require python3-venv

[L0] $ wget https://download.qemu.org/qemu-8.0.0.tar.bz2
[L0] $ tar -xvf qemu-8.0.0.tar.bz2
[L0] $ cd qemu
[L0] $ patch -p1 < /path/to/HyperPill/hyperpill-snap/hp-snap-qemu.patch
[L0] $ mkdir build; cd build;
[L0] $ ../configure --target-list=x86_64-softmmu
[L0] $ ninja -j$(nproc)

# Now use the build qemu to create a single-CPU VM [L1] and install a hypervisor
# within it. Configure a linux VM [L2] within the hypervisor. Running L1 VM with
# 8GB mem is recommended, so that L1 VM can have a full 4GB mem.
```

### Run L1 and L2 VMs for QEMU/KVM

``` bash
[L0] $ wget https://cloud.debian.org/images/cloud/bookworm/daily/20240827-1852/debian-12-nocloud-amd64-daily-20240827-1852.qcow2 --no-check-certificate
[L0] $ qemu-img resize debian-12-nocloud-amd64-daily-20240827-1852.qcow2 20G
[L0] $ qemu/build/qemu-system-x86_64 -machine q35 -accel kvm -m 8G \
    -cpu host,-pku,-xsaves,-kvmclock,-kvm-pv-unhalt \
    -netdev user,id=u1,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=u1 -smp 1 -serial stdio \
    -hda debian-12-nocloud-amd64-daily-20240827-1852.qcow2 \
    -monitor telnet:127.0.0.1:55556,server,nowait
# Type root (no password) to enter L1 VM
[L1] $ apt-get update && apt-get install -y cloud-utils xarchiver
[L1] $ growpart /dev/sda 1
[L1] $ resize2fs /dev/sda1
[L1] $ df -h

[L1] $ apt-get install -y git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build libslirp-dev
[L1] $ apt-get install -y python3 python3-pip python3-venv

# Setup the QEMU under test - example 1: QEMU 8.0.0 with ASAN
[L1] $ wget https://download.qemu.org/qemu-8.0.0.tar.bz2
[L1] $ tar xf qemu-8.0.0.tar.bz2
[L1] $ cd qemu-8.0.0
[L1] $ mkdir build; cd build;
[L1] $ ../configure --target-list=x86_64-softmmu --enable-slirp --enable-sanitizers
[L1] $ ninja

# Setup the QEMU under test - example 2: QEMU 9.0.0 without ASAN just for coverage comparison
[L1] $ wget https://download.qemu.org/qemu-9.0.0.tar.bz2
[L1] $ tar xf qemu-9.0.0.tar.bz2
[L1] $ cd qemu-9.0.0
[L1] $ mkdir build; cd build;
[L1] $ ../configure --target-list=x86_64-softmmu --enable-slirp
[L1] $ ninja

[L1] $ wget https://github.com/HexHive/HyperPill/raw/main/hyperpill-snap/bzImage
[L1] $ wget https://github.com/HexHive/HyperPill/raw/main/hyperpill-snap/rootfs.cpio.gz
[L1] $ apt-get install -y swtpm
[L1] $
rm -rf /tmp/mytpm1; mkdir /tmp/mytpm1
pkill swtpm
swtpm socket --tpmstate dir=/tmp/mytpm1 \
  --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock \
  --tpm2 \
  --log level=20 \
  --daemon
qemu-8.0.0/build/qemu-system-x86_64 -machine q35 -accel kvm -m 4G \
    -device ac97,audiodev=snd0 -audiodev none,id=snd0 \
    -device cs4231a,audiodev=snd1 -audiodev none,id=snd1 \
    -device intel-hda,id=hda0 -device hda-output,bus=hda0.0 -device hda-micro,bus=hda0.0 -device hda-duplex,bus=hda0.0 \
    -device sb16,audiodev=snd2 -audiodev none,id=snd2 \
    -drive file=null-co://,if=none,format=raw,id=disk0 -drive file=null-co://,if=none,format=raw,id=disk1 \
    -drive file=null-co://,if=none,format=raw,id=disk2 -drive file=null-co://,if=none,format=raw,id=disk3 \
    -drive file=null-co://,if=none,format=raw,id=disk4 -drive file=null-co://,if=none,format=raw,id=disk5 \
    -drive file=null-co://,if=none,format=raw,id=disk6 -drive file=null-co://,if=none,format=raw,id=disk7 \
    -drive file=null-co://,if=none,format=raw,id=disk8 -drive file=null-co://,if=none,format=raw,id=disk9 \
    -blockdev driver=null-co,read-zeroes=on,node-name=null0 \
    -device ide-cd,drive=disk1 \
    -device isa-fdc,id=floppy0 \
    -device qemu-xhci,id=xhci \
    -device usb-tablet,bus=xhci.0 -device usb-bot -device usb-storage,drive=disk3 \
    -chardev null,id=cd0 -chardev null,id=cd1 -device usb-braille,chardev=cd0 -device usb-serial,chardev=cd1 \
    -device usb-ccid -device usb-ccid -device usb-kbd -device usb-mouse \
    -device usb-tablet -device usb-wacom-tablet -device usb-audio \
    -device ich9-usb-ehci1,bus=pcie.0,addr=1d.7,multifunction=on,id=ich9-ehci-1 \
    -device ich9-usb-uhci1,bus=pcie.0,addr=1d.0,multifunction=on,masterbus=ich9-ehci-1.0,firstport=0 \
    -device ich9-usb-uhci2,bus=pcie.0,addr=1d.1,multifunction=on,masterbus=ich9-ehci-1.0,firstport=2 \
    -device ich9-usb-uhci3,bus=pcie.0,addr=1d.2,multifunction=on,masterbus=ich9-ehci-1.0,firstport=4 \
    -device usb-tablet,bus=ich9-ehci-1.0,port=1,usb_version=1 \
    -drive if=none,id=usbcdrom,media=cdrom -device usb-storage,bus=ich9-ehci-1.0,port=2,drive=usbcdrom \
    -device pci-ohci -device usb-kbd \
    -device megasas \
    -drive if=none,index=30,file=null-co://,format=raw,id=mydrive \
    -device scsi-cd,drive=null0 -device sdhci-pci,sd-spec-version=3 -device sd-card,drive=mydrive \
    -device virtio-blk,drive=disk4 -device virtio-scsi,num_queues=8 -device scsi-hd,drive=disk5 \
    -device e1000,netdev=net0 -netdev user,id=net0 \
    -device e1000e,netdev=net1 -netdev user,id=net1 \
    -device igb,netdev=net2 -netdev user,id=net2 \
    -device i82550,netdev=net3 -netdev user,id=net3 \
    -device ne2k_pci,netdev=net4 -netdev user,id=net4 \
    -device pcnet,netdev=net5 -netdev user,id=net5 \
    -device rtl8139,netdev=net6 -netdev user,id=net6 \
    -device vmxnet3,netdev=net7 -netdev user,id=net7 \
    -device ati-vga -device cirrus-vga -device virtio-gpu \
    -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
    -object cryptodev-backend-builtin,id=cryptodev0 -device virtio-crypto-pci,id=crypto0,cryptodev=cryptodev0 \
    -drive file=null-co://,if=none,id=nvm -device nvme,serial=deadbeef,drive=nvm \
    -monitor stdio -append console=ttyS0 -kernel bzImage -initrd rootfs.cpio.gz
    # -device qxl-vga \
```

### Run L1 and L2 VMs for macOS Virtualization Framework

``` bash
[L0] $ git clone https://github.com/kholia/OSX-KVM.git
[L0] $ cd OSX-KVM
[L0] $ git checkout 422bb3b7137cd13468aee86de3640835e1d774f9
[L0] $ patch -p 1 < /path/to/HyperPill/hyperpill-snap/osx-kvm.patch # to enable vmx

# download ventura image
[L0] $ follow https://github.com/kholia/OSX-KVM?tab=readme-ov-file#installation-preparation
# install ventura and setup username/password, e.g., macos/macos
[L0] $ follow https://github.com/kholia/OSX-KVM?tab=readme-ov-file#installation
[L0] $ bash -x OpenCore-Boot.sh # 1 vcpus and 4GB mem
# [L0] $ ssh macos@localhost -p 2222

[L1] $ see the option 2 of
https://www.freecodecamp.org/news/how-to-download-and-install-xcode/ and install
xcode 14.3.1 for macos ventura

[L1] $ download ubuntu\'s desktop ISO image via
https://releases.ubuntu.com/jammy/ubuntu-22.04.4-desktop-amd64.iso

[L1] $ download [the sample
code](https://developer.apple.com/documentation/virtualization/running_gui_linux_in_a_virtual_machine_on_a_mac)
for Running GUI Linux in a virtual machine on a Mac

[L1] load the project with xcode, run the project, choose the ubuntu desktop ISO
image, install ubuntu, and restart the ubuntu
```

### [Optional] Obtain Symbols for Debugging

``` bash
# install the debugging symbols for the Linux kernel
[L1] uname -r # 6.1.0-23-amd64
[L1] sudo apt-get install -y linux-image-$(uname -r)-dbg
[L1] cd qemu-8.0.0/build && ldd qemu-system-x86_64
# linux-vdso.so.1 (0x00007ffea85f8000)
# libasan.so.8 => /lib/x86_64-linux-gnu/libasan.so.8 (0x00007f3250800000)
# libpixman-1.so.0 => /lib/x86_64-linux-gnu/libpixman-1.so.0 (0x00007f3253b7c000)
# libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f3253b5d000)
# libfdt.so.1 => /lib/x86_64-linux-gnu/libfdt.so.1 (0x00007f3253b52000)
# libgio-2.0.so.0 => /lib/x86_64-linux-gnu/libgio-2.0.so.0 (0x00007f3250620000)
# libgobject-2.0.so.0 => /lib/x86_64-linux-gnu/libgobject-2.0.so.0 (0x00007f3253af1000)
# libglib-2.0.so.0 => /lib/x86_64-linux-gnu/libglib-2.0.so.0 (0x00007f3250ec8000)
# libslirp.so.0 => /lib/x86_64-linux-gnu/libslirp.so.0 (0x00007f3253acd000)
# libgmodule-2.0.so.0 => /lib/x86_64-linux-gnu/libgmodule-2.0.so.0 (0x00007f3253ac7000)
# libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f3250541000)
# libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f3250ea8000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3250360000)
# /lib64/ld-linux-x86-64.so.2 (0x00007f3253c31000)
# libmount.so.1 => /lib/x86_64-linux-gnu/libmount.so.1 (0x00007f32502fd000)
# libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f32502cf000)
# libffi.so.8 => /lib/x86_64-linux-gnu/libffi.so.8 (0x00007f3253ab9000)
# libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f3250235000)
# libblkid.so.1 => /lib/x86_64-linux-gnu/libblkid.so.1 (0x00007f32501de000)

# copy the debugging symbols for the Linux kernel and kvm
[L0] cd /path/to/snapshots/dir/symbols
[L0] scp -P 2222 root@localhost:/usr/lib/debug/boot/vmlinux-6.1.0-23-amd64 vmlinux
[L0] scp -P 2222 root@localhost:/usr/lib/debug/lib/modules/6.1.0-23-amd64/kernel/arch/x86/kvm/kvm-intel.ko .
[L0] scp -P 2222 root@localhost:/usr/lib/debug/lib/modules/6.1.0-23-amd64/kernel/arch/x86/kvm/kvm.ko .
# copy the debugging symbols for the QEMU
[L0] scp -P 2222 root@localhost:/lib/x86_64-linux-gnu/libc.so.6 .
[L0] scp -P 2222 root@localhost:/lib/x86_64-linux-gnu/libglib-2.0.so.0 .
[L0] scp -P 2222 root@localhost:/lib/x86_64-linux-gnu/libslirp.so.0 .
[L0] scp -P 2222 root@localhost:/root/qemu-8.0.0/build/qemu-system-x86_64 .
```

## Take the snapshot

``` bash
# In L2, we use the following tool to trigger a snapshot.
# We include snap in rootfs.cpio.gz
[L2] $ snap

# But in other L2 VM, we have to compile snap.c
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

# Now in L0, collect the snapshot data to /path/to/snapshots/dir,
# where dir can be `kvm`, `hyperv`, `macos`, or whatever you want.
# Attach to qemu monitor:
[L0] $ telnet localhost 55556
[L0 qemu-monitor] dump-guest-memory /path/to/snapshots/dir/mem
[L0 qemu-monitor] info registers
# Copy the output of the above command to /path/to/snapshots/dir/regs
[L0] sudo dmesg | grep "VMCS.*last" | cut -f2 -d"(" | cut -f1 -d ")"
# Copy the output of the above command to /path/to/snapshots/dir/vmcs
```

The snapshot should now be ready for input-space-emulation and fuzzing.
