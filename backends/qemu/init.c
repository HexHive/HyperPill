#include "qemu.h"

extern void el_change_fn(ARMCPU *cpu, void *opaque);
extern void pre_el_change_fn(ARMCPU *cpu, void *opaque);
extern void before_exec_tb_fn(int cpu_index, TranslationBlock *tb);
extern void after_exec_tb_fn(int cpu_index, TranslationBlock *tb);

void icp_init_backend() {
	int qemu_argc = 22;
	char *qemu_argv[] = {
		"qemu-system-aarch64",
		"-nographic",
		"-smp", "1",
		"-m", "8192", // TODO: we assume at most 8G?
		"-cpu", "max",
        "-L", "pc-bios",
		"-M", "virt,virtualization=on,suppress-vmdesc=on",
        "-global", "migration.send-configuration=off",
        "-global", "migration.store-global-state=off",
        "-global", "migration.send-section-footer=off",
		"-netdev", "user,id=net0",
		"-device", "virtio-net-device,netdev=net0",
		NULL
	};
    qemu_init(qemu_argc, qemu_argv);

    arm_register_el_change_hook(ARM_CPU(QEMU_CPU(0)), el_change_fn, NULL);
    arm_register_pre_el_change_hook(ARM_CPU(QEMU_CPU(0)), pre_el_change_fn, NULL);
    register_exec_tb_cb(before_exec_tb_fn, after_exec_tb_fn);
}
