#include "fuzz.h"
extern uint8_t* random_register_data;
extern size_t random_register_data_len;
extern std::map<int, std::tuple<uint8_t*, size_t>> register_contents;

bool fuzz_hook_vmlaunch() {
    /* printf("Vmlaunch:%lx\n", BX_CPU(id)->vmcsptr); */
    if(vmcs_addr == BX_CPU(id)->vmcsptr){
        fuzz_emu_stop_normal();
        return true;
    }

    return false;
}

size_t init_random_register_data_len(void) {
    return 16 * 8 + (BX_XMM_REGISTERS + 1) * sizeof(BX_CPU(id)->vmm[0]);
}

void init_register_feedback(void) {
    // 16 General-Purpose Registers + 16 XMM Registers
    /* int fd = open("/dev/random", O_RDONLY); */
    srand(0);
    random_register_data = (uint8_t*) malloc(random_register_data_len);
    /* read(fd, random_register_data, random_register_data_len); */
    uint8_t* cursor = random_register_data;
    for(int i=0; i<16; i++) {
            if(i == BX_64BIT_REG_RSP || i == BX_64BIT_REG_RBP)
                continue;
            uint64_t value;
            uint8_t* ptr = (uint8_t*)&value;
            for(int j=0; j<sizeof(value); j++)
                ptr[j] = rand();
            memcpy(cursor, &value, sizeof(value));
            BX_CPU(id)->set_reg64(i, value);
            register_contents[i] = std::make_pair(cursor, 8);
            cursor += 8;
            printf("REG%d: %lx\n", i, value);
    }
    for(int i=0; i<BX_XMM_REGISTERS+1; i++) {
            uint8_t* ptr = (uint8_t*)&BX_CPU(id)->vmm[i];
            for(int j=0; j<sizeof(BX_CPU(id)->vmm[i]); j++)
                ptr[j] = rand();
            memcpy(cursor, &BX_CPU(id)->vmm[i], sizeof(BX_CPU(id)->vmm[i]));
            register_contents[16+i] = std::make_pair(cursor, sizeof(BX_CPU(id)->vmm[i]));
            cursor += sizeof(BX_CPU(id)->vmm[i]);
    }
}
