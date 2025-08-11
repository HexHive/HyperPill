# HP-Snap Instructions for seL4

Download seL4's libvmm

```
git clone https://github.com/au-ts/libvmm
cd examples/virtio
```

Patch virtio.mk

```
diff --git a/examples/virtio/virtio.mk b/examples/virtio/virtio.mk
index e89f3b7..a0f1678 100644
--- a/examples/virtio/virtio.mk
+++ b/examples/virtio/virtio.mk
@@ -3,7 +3,7 @@
 #
 # SPDX-License-Identifier: BSD-2-Clause
 #
-QEMU := qemu-system-aarch64
+QEMU := /home/debian/Inception/qemu-8.2.7/build/qemu-system-aarch64
 PYTHON ?= python3

 LIBVMM_DOWNLOADS := https://trustworthy.systems/Downloads/libvmm/images/
@@ -166,17 +166,20 @@ client_vmm.elf: client_vm/vmm.o client_vm/images.o |vm_dir

 qemu: $(IMAGE_FILE) blk_storage
 	[ ${MICROKIT_BOARD} = qemu_virt_aarch64 ]
-	$(QEMU) -machine virt,virtualization=on,secure=off \
-			-cpu cortex-a53 \
-			-serial mon:stdio \
-			-device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
-			-m size=2G \
-			-nographic \
-			-global virtio-mmio.force-legacy=false \
-			-drive file=blk_storage,format=raw,if=none,id=drive0 \
-			-device virtio-blk-device,drive=drive0,id=virtblk0,num-queues=1 \
-			-device virtio-net-device,netdev=netdev0 \
-			-netdev user,id=netdev0,hostfwd=tcp::1236-:1236,hostfwd=tcp::1237-:1237,hostfwd=udp::1235-:1235 \
+	$(QEMU) -machine virt,virtualization=on,secure=off,suppress-vmdesc=on \
+			-monitor telnet:127.0.0.1:55556,server,nowait \
+			-smp 1 -m 2G -cpu cortex-a53 \
+			-serial mon:stdio \
+			-device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
+			-nographic \
+			-global virtio-mmio.force-legacy=false \
+			-drive file=blk_storage,format=raw,if=none,id=drive0 \
+			-device virtio-blk-device,drive=drive0,id=virtblk0,num-queues=1 \
+			-device virtio-net-device,netdev=netdev0 \
+			-netdev user,id=netdev0 \
+			-global migration.send-configuration=off \
+			-global migration.store-global-state=off \
+			-global migration.send-section-footer=off

 clean::
 	$(RM) -f *.elf .depend* $
```

Prepare microkit-sdk-2.0.1 and arm-gnu-toolchain-12.3.rel1-x86_64-aarch64-none-elf

```
export PATH=$PATH:path/to/arm-gnu-toolchain-12.3.rel1-x86_64-aarch64-none-elf/bin
make \
    MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_SDK=path/to/microkit-sdk-2.0.1 \
    LINUX=/abs/path/to/HyperPill-for-arm64/hyperpill-snap/aarch64/Image \
    INITRD=/abs/path/to/HyperPill-for-arm64/hyperpill-snap/aarch64/rootfs.cpio.gz \
    qemu
``

All good but there lacks of instrumentation to detect bugs or collect coverage
for all components such as seL4 itself, libvmm, and sddf.

