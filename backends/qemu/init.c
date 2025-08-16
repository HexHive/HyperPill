#include "qemu.h"

void icp_init_backend() {
	int qemu_argc = 21;
	const char *m, *cpu;
	if (getenv("SEL4")) {
		m = "2048";
		cpu = "cortex-a53";
	} else {
		m = "8192";
		cpu = "max";
	}
	char *qemu_argv[] = {
		"qemu-system-aarch64",
		"-chardev", "stdio,id=char0,signal=on",
		"-serial", "chardev:char0",
		"-smp", "1",
		"-m", m,
		"-cpu", cpu,
        "-L", "pc-bios",
		"-M", "virt,virtualization=on,suppress-vmdesc=on",
        "-global", "migration.send-configuration=off",
        "-global", "migration.store-global-state=off",
        "-global", "migration.send-section-footer=off",
		NULL
	};
    qemu_init(qemu_argc, qemu_argv);

    arm_register_el_change_hook(ARM_CPU(QEMU_CPU(0)), el_change_fn, NULL);
    arm_register_pre_el_change_hook(ARM_CPU(QEMU_CPU(0)), pre_el_change_fn, NULL);
    register_exec_tb_cb(before_exec_tb_fn, after_exec_tb_fn);
	hp_qemu_plugin_load();

    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
}
