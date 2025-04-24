#include "qemu.h"

bool fuzz_hook_back_to_el1_kernel(void) {
    // fuzz_emu_stop_normal();
    return true;
}

bool __fuzz_emu_stop_normal(void) {
    // fuzz_emu_stop_normal();
    return true;
}

void init_register_feedback(void) {
}
