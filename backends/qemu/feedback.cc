#include "fuzz.h"
extern uint8_t* random_register_data;
extern size_t random_register_data_len;
extern std::map<int, std::tuple<uint8_t*, size_t>> register_contents;

extern "C"
bool fuzz_hook_back_to_el1_kernel(void) {
    fuzz_emu_stop_normal();
    return true;
}

extern "C"
bool __fuzz_emu_stop_normal(void) {
    fuzz_emu_stop_normal();
    return true;
}

size_t init_random_register_data_len(void) {
    return 0; // TODO
}

void init_register_feedback(void) {
}
