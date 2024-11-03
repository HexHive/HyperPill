#include "fuzz.h"
extern uint8_t* random_register_data;
extern size_t random_register_data_len;
extern std::map<int, std::tuple<uint8_t*, size_t>> register_contents;

size_t init_random_register_data_len(void) {
    return 0; // TODO
}

void init_register_feedback(void) {
}
