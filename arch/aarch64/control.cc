#include "fuzz.h"
#include "qemuapi.h"

bool cpu0_get_fuzztrace(void) {
    return __cpu0_get_fuzztrace();
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    __cpu0_set_fuzztrace(fuzztrace);
}

void cpu0_set_fuzz_executing_input(bool fuzzing) {
    __cpu0_set_fuzz_executing_input(fuzzing);
}

bool cpu0_get_fuzz_executing_input(void) {
    return __cpu0_get_fuzz_executing_input();
}