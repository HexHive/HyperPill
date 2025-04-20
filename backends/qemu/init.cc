void init_backend() {
	int qemu_argc = 20;
	char *qemu_argv[] = {
		"qemu-system-aarch64",
		"-smp", "1",
		"-m", "8192",
		"-cpu", "max",
		"-M", "virt,virtualization=on",
		NULL
	};
	init_qemu(qemu_argc, qemu_argv, __snapshot_tag);
}