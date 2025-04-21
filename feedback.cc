#include "fuzz.h"
#include <tsl/robin_set.h>
#include <unordered_set>
#include <map>

uint8_t* random_register_data;
size_t random_register_data_len = init_random_register_data_len();

std::map<int, std::tuple<uint8_t*, size_t>> register_contents;

std::unordered_set<uint64_t> indicator_values;

std::map<uint64_t, uint64_t> found_indicators;
std::map<uint64_t, uint64_t> total_indicators;

struct Hasher {
    std::size_t operator()(std::tuple<uint64_t, uint64_t, uint64_t> const& key) const { 
            return std::hash<uint64_t>{}(std::get<0>(key)) ^
            (std::hash<uint64_t>{}(std::get<1>(key)) << 1) ^
            (std::hash<uint64_t>{}(std::get<2>(key)) << 2);
    }
};

tsl::robin_set<std::tuple<uint64_t, uint64_t, uint64_t>, Hasher> structset;

#if defined(HP_X86_64)
bool fuzz_hook_vmlaunch() {
    /* printf("Vmlaunch:%lx\n", cpu0_get_vmcsptr()); */
    if(vmcs_addr == cpu0_get_vmcsptr()) {
        fuzz_emu_stop_normal();
        return true;
    }

    return false;
}
#endif

extern "C" void __sanitizer_cov_trace_cmp1_pc(uint64_t PC, uint8_t Arg1, uint8_t Arg2);
extern "C" void __sanitizer_cov_trace_cmp2_pc(uint64_t PC, uint16_t Arg1, uint16_t Arg2);
extern "C" void __sanitizer_cov_trace_cmp4_pc(uint64_t PC, uint32_t Arg1, uint32_t Arg2);
extern "C" void __sanitizer_cov_trace_cmp8_pc(uint64_t PC, uint64_t Arg1, uint64_t Arg2);


void add_indicator_value(uint64_t val) {
    /* while(val && !(val&1)) */
    /*     val = val>>1; */
    indicator_values.insert(val);
}

void clear_indicator_values() {
    indicator_values.clear();
}

void aggregate_indicators() {
    for(auto it = found_indicators.begin(); it != found_indicators.end(); ++it) {
        total_indicators[it->first] += 1;
    }
}

void dump_indicators() {
    for(auto it = total_indicators.begin(); it != total_indicators.end(); ++it) {
        printf("%lx: %lx\n", it->first, it->second);
    }
}
void indicator_cb(void(*cb)(uint64_t)) {
    for(auto it = total_indicators.begin(); it != total_indicators.end(); ++it) {
        cb(it->first);
    }
}

void fuzz_hook_cmp(uint64_t op1, uint64_t op2, size_t size){


    uint64_t PC = cpu0_get_pc();
    if(cpu0_get_fuzztrace())
        printf("CMP%ld: %lx vs %lx @ %lx\n", size, op1, op2, PC);


    if(!op1 || !op2 || op1 == op2 || size < 2)
        return;
    if(ignore_pc(PC))
        return;

    if (indicator_values.find(op1) != indicator_values.end()) {
        found_indicators[op2]+=1;
    }

    if (indicator_values.find(op2) != indicator_values.end()) {
        found_indicators[op1]+=1;
    }

    for(int i=0; i<2 && random_register_data ; i++){
        uint8_t* start = (uint8_t*)(i ? &op1: &op2);
        uint8_t* end = start + size-1;
        while(end>start){
            if(!*end) {
                end--;
            } else {
                break;
            }
        }
        while(start<end){
            if(!*start) {
                start++;
            } else {
                break;
            }
        }

        if(end-start > 2) {
            uint8_t *found  = (uint8_t*)memmem(random_register_data, random_register_data_len, start, end-start);
            if(found) {
                for (auto it=register_contents.begin(); it!=register_contents.end(); ++it) {
                    uint8_t* ptr = std::get<0>(it->second);
                    size_t len = std::get<1>(it->second);
                    if(found >= ptr && found+ (end-start) <= ptr + len) {
                        /* printf("Likely Found Register: %x. Match Size: %ld CMP: %lx vs %lx\n", end-start, it->first, op1, op2); */
                        insert_register_value_into_fuzz_input(it->first);
                    }
                }
            }
        }
    }

    switch(size) {
        case 2:
            __sanitizer_cov_trace_cmp2_pc(PC, (uint16_t)op1, (uint16_t)op2);
        case 4:
            __sanitizer_cov_trace_cmp4_pc(PC, op1, op2);
            break;
        case 8:
            __sanitizer_cov_trace_cmp8_pc(PC, op1, op2);
            break;
        default:
            break;
    }

}

void init_register_feedback() {
#if defined(HP_X86_64)
    // 16 General-Purpose Registers + 16 XMM Registers
#elif defined(HP_AARCH64)
    // 31 General-Purpose Registers
#endif
    /* int fd = open("/dev/random", O_RDONLY); */
    srand(0);
    random_register_data = (uint8_t*) malloc(random_register_data_len);
    /* read(fd, random_register_data, random_register_data_len); */
    uint8_t* cursor = random_register_data;
#if defined(HP_X86_64)
    for(int i=0; i<16; i++) {
            if(i == BX_64BIT_REG_RSP || i == BX_64BIT_REG_RBP)
                continue;
#elif defined(HP_AARCH64)
    for(int i=0; i<31; i++) {
#endif
            uint64_t value;
            uint8_t* ptr = (uint8_t*)&value;
            for(int j=0; j<sizeof(value); j++)
                ptr[j] = rand();
            memcpy(cursor, &value, sizeof(value));
            cpu0_set_general_purpose_reg64(i, value);
            register_contents[i] = std::make_pair(cursor, 8);
            cursor += 8;
            printf("REG%d: %lx\n", i, value);
    }
#if defined(HP_X86_64)
    for(int i=0; i<BX_XMM_REGISTERS+1; i++) {
            uint8_t* ptr = (uint8_t*)&BX_CPU(id)->vmm[i];
            for(int j=0; j<sizeof(BX_CPU(id)->vmm[i]); j++)
                ptr[j] = rand();
            memcpy(cursor, &BX_CPU(id)->vmm[i], sizeof(BX_CPU(id)->vmm[i]));
            register_contents[16+i] = std::make_pair(cursor, sizeof(BX_CPU(id)->vmm[i]));
            cursor += sizeof(BX_CPU(id)->vmm[i]);
    }
#endif
}
