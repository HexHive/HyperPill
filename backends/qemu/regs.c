#include "qemu.h"

//std::cout << "  submatch " << i << ": " << piece << '\n';
#define GETREG32(REG) \
({\
    uint32_t val;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %x\n", match[1].str().c_str(), val); \
    val;\
})

#define GETREG64(REG) \
({\
    uint64_t val;\
    std::stringstream ss; \
    std::regex reg_regex("\\b"#REG "\\s*=\\s*(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %lx\n", match[1].str().c_str(), val); \
    val;\
})


#define LOADREG(NREG, REG ) \
{\
    uint64_t val;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %lx\n", match[1].str().c_str(), val); \
    BX_CPU(id)->set_reg64(NREG, val); \
};

#define LOADSEG(NREG, REG ) \
{\
    uint16_t raw_selector;\
    uint64_t base;\
    uint32_t limit_scaled;\
    uint32_t ar_data;\
    bool present =1;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+DPL.*"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    if(match.size() < 1){\
        std::regex reg_regex2(#REG "\\s*=(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+(\\w+)"); \
        std::regex_search(s, match, reg_regex2);\
        present = 0;\
    }\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> raw_selector;\
    ss.clear();\
    ss << std::hex << match[2].str(); \
    ss >> base;\
    ss.clear();\
    ss << std::hex << match[3].str(); \
    ss >> limit_scaled;\
    ss.clear();\
    ss << std::hex << match[4].str(); \
    ss >> ar_data;\
    ar_data = (ar_data >> 8);\
    ss.clear();\
    printf(".info " #REG ": present=%d %x %lx %x %x\n", present, raw_selector, base, limit_scaled, ar_data); \
    BX_CPU(id)->set_segment_ar_data(NREG , \
            present, raw_selector, base, limit_scaled, ar_data);\
};
    /* BX_CPU(id)->set_segment_ar_data(NREG , \ */
    /*         (ar_data >> 8) & 1, raw_selector, base, limit_scaled, ar_data);\ */

#define LOADDT(NREG, REG ) \
{\
    uint64_t base;\
    uint16_t limit;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "=\\s*(\\w+)\\s+(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> base;\
    ss.clear();\
    ss << std::hex << match[2].str(); \
    ss >> limit;\
    ss.clear();\
    printf(".info " #REG ": %lx %x\n", base, limit); \
    NREG.base = base;\
    NREG.limit = limit;\
};

void icp_init_regs(const char* filename) {
	assert(0);
}

void dump_regs() {
    cpu_dump_state(QEMU_CPU(0), NULL, CPU_DUMP_FPU);
	fflush(stdout);
	fflush(stderr);
}

uint64_t cpu0_get_pc(void) {
    return (&(ARM_CPU(QEMU_CPU(0)))->env)->pc;
}

void cpu0_set_pc(uint64_t pc) {
    (&(ARM_CPU(QEMU_CPU(0)))->env)->pc = pc;
}

size_t init_random_register_data_len(void) {
	assert(0);
}

bool cpu0_get_user_pl(void) {
	assert(0);
}

void save_cpu() {
	shadow_qemu_cpu = qemu_cpu;
}

void restore_cpu() {
	qemu_cpu = shadow_qemu_cpu;
}

void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value) {
	 assert(0);
}