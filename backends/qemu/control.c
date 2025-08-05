#include "qemu.h"

bool cpu0_get_fuzztrace(void) {
    return QEMU_CPU(0)->fuzztrace;
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    QEMU_CPU(0)->fuzztrace = fuzztrace;
}

void cpu0_set_fuzz_executing_input(bool fuzzing) {
    QEMU_CPU(0)->fuzz_executing_input = fuzzing;
}

bool cpu0_get_fuzz_executing_input(void) {
    return QEMU_CPU(0)->fuzz_executing_input;
}

void cpu0_run_loop() {
    vm_start();

    while (cpu0_get_fuzz_executing_input()) {
        main_loop_wait(false);
    }
}
