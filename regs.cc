#include <sstream>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <cstdint>
#include <regex>

#include "bochs.h"
#include "cpu/cpu.h"
#include "cpu/vmx.h"

BX_CPU_C bx_cpu = BX_CPU_C(0);
BX_CPU_C shadow_bx_cpu;

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
    std::ifstream t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();

    printf(".loading registers from %s\n", filename);
    std::string s = buffer.str();

    uint64_t val = GETREG64(RIP);
    BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = val;
    BX_CPU(id)->prev_rip = val;
    

    val = GETREG64(RSP);
    BX_CPU(id)->gen_reg[BX_64BIT_REG_RSP].rrx = val;
    BX_CPU(id)->prev_rsp = val;

    LOADREG(0, RAX);
    LOADREG(1, RCX);
    LOADREG(2, RDX);
    LOADREG(3, RBX);
    LOADREG(5, RBP);
    LOADREG(6, RSI);
    LOADREG(7, RDI);
    LOADREG(8, R8);
    LOADREG(9, R9);
    LOADREG(10, R10);
    LOADREG(11, R11);
    LOADREG(12, R12);
    LOADREG(13, R13);
    LOADREG(14, R14);
    LOADREG(15, R15);

    BX_CPU(id)->setEFlags(GETREG64(RFL));

    LOADSEG(&BX_CPU(id)->sregs[0], ES );
    LOADSEG(&BX_CPU(id)->sregs[1], CS );
    LOADSEG(&BX_CPU(id)->sregs[2], SS );
    LOADSEG(&BX_CPU(id)->sregs[3], DS );
    LOADSEG(&BX_CPU(id)->sregs[4], FS );
    LOADSEG(&BX_CPU(id)->sregs[5], GS );

    LOADSEG(&BX_CPU(id)->ldtr, LDT );
    LOADSEG(&BX_CPU(id)->tr, TR );
    
    LOADDT(BX_CPU(id)->gdtr, GDT );
    LOADDT(BX_CPU(id)->idtr, IDT );

    BX_CPU(id)->dr[0] = GETREG64(DR0);
    BX_CPU(id)->dr[1] = GETREG64(DR1);
    BX_CPU(id)->dr[2] = GETREG64(DR2);
    BX_CPU(id)->dr[3] = GETREG64(DR3);
    BX_CPU(id)->dr6.set32(GETREG32(DR6));
    BX_CPU(id)->dr7.set32(GETREG32(DR7));
    
    BX_CPU(id)->cr0.set32(GETREG32(CR0));
    BX_CPU(id)->cr2 = GETREG64(CR2);
    BX_CPU(id)->cr3 = GETREG64(CR3);
    BX_CPU(id)->cr4.set32(GETREG32(CR4));
    if (!getenv("NOCOV")) {
        BX_CPU(id)->cr4.set_SMAP(false);
    }
    
    BX_CPU(id)->xcr0.set32(0b11100111);

    BX_CPU(id)->msr.kernelgsbase = GETREG64(kernelgsbase);
    BX_CPU(id)->msr.sysenter_cs_msr = GETREG64(sysenter_cs);
    BX_CPU(id)->msr.sysenter_esp_msr = GETREG64(sysenter_esp);
    BX_CPU(id)->msr.sysenter_eip_msr = GETREG64(sysenter_eip);
    BX_CPU(id)->efer.set32(GETREG32(EFER));
    BX_CPU(id)->msr.star = GETREG64(star); // Check it
    BX_CPU(id)->msr.lstar = GETREG64(lstar);
    BX_CPU(id)->msr.cstar = GETREG64(cstar);
    BX_CPU(id)->msr.fmask = GETREG64(fmask);
    
    BX_CPU(id)->set_TSC(GETREG64(tsc_deadline));
    BX_CPU(id)->msr.tsc_aux = GETREG64(tsc_aux);
    
    BX_CPU(id)->msr.pat._u64 = GETREG64(pat);
    BX_CPU(id)->msr.apicbase = GETREG64(apicbase);
    

    BX_CPU(id)->TLB_flush();
#if BX_CPU_LEVEL >= 4
    BX_CPU(id)->handleAlignmentCheck(/* CR0.AC reloaded */);
#endif

    BX_CPU(id)->handleCpuModeChange();

#if BX_CPU_LEVEL >= 6
    BX_CPU(id)->handleSseModeChange();
    BX_CPU(id)->handleAvxModeChange();
#endif

    BX_CPU(id)->lapic.set_lvt_entry(BX_LAPIC_LVT_TIMER, 0x000400ec);


    BX_CPU(id)->the_i387.cwd=0x037F;
    BX_CPU(id)->the_i387.swd = 0;
    BX_CPU(id)->the_i387.tos = 0;
    BX_CPU(id)->the_i387.twd = 0xFFFF;
    BX_CPU(id)->the_i387.foo = 0;
    BX_CPU(id)->the_i387.fip = 0;
    BX_CPU(id)->the_i387.fcs = 0;
    BX_CPU(id)->the_i387.fds = 0;
    BX_CPU(id)->the_i387.fdp = 0;
}

void icp_set_vmcs(uint64_t vmcs) {
    /* BX_CPU(id)->vmcshostptr = BX_CPU(id)->getHostMemAddr(vmcs, BX_WRITE); */
    for(int i=0; i<0x10000; i+=0x1000)
        BX_CPU(id)->getHostMemAddr(vmcs+i, BX_WRITE);
    BX_CPU(id)->vmcsptr = vmcs;
    BX_CPU(id)->vmxonptr = 0xdeadbeef;
    BX_CPU(id)->in_vmx = true;
    BX_CPU(id)->vmcs.eptptr = (bx_phy_address) BX_CPU(id)->VMread64(VMCS_64BIT_CONTROL_EPTPTR);
    BX_CPU(id)->VMwrite32(VMCS_LAUNCH_STATE_FIELD_ENCODING, VMCS_STATE_LAUNCHED);
    BX_CPU(id)->vmcs_map->set_access_rights_format(VMCS_AR_OTHER);
}


void fuzz_reset_registers() {
}

uint64_t cpu0_get_pc(void) {
  return BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx;
}

void cpu0_set_pc(uint64_t rip) {
	BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = rip;
}

uint64_t cpu0_get_vmcsptr(void) {
    return BX_CPU(id)->vmcsptr;
}

bool cpu0_get_user_pl(void) {
    return BX_CPU(id)->user_pl;
}

void save_cpu() {
    shadow_bx_cpu = bx_cpu;
}

void restore_cpu() {
    bx_cpu = shadow_bx_cpu;
}
