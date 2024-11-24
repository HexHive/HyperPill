#include "qemu_c.h"
#include "qemuapi.h"

void init_qemu(int argc, char **argv) {
    qemu_init(argc, argv);
    qemu_main_loop();
    qemu_cleanup(0);
}

//void arm_register_el_change_hook(ARMCPU *cpu, ARMELChangeHookFn *hook, void
//        *opaque);

//void cpu_physical_memory_rw(hwaddr addr, void *buf,
//                            hwaddr len, bool is_write); 
//void qemu_init(int argc, char **argv);
//int qemu_main_loop(void);
//void qemu_cleanup(int);