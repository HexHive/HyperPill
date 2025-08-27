#include "fuzz.h"
#include "cpu/vmx.h"
#include <sstream>
#include <fstream>
#include <regex>
#include <vector>
#include <unordered_map>

std::unordered_map<uint64_t, uint64_t> shadow_vmcs_layout;

void fuzz_hook_vmptrld(Bit64u vmcs){
}

bool fuzz_hook_vmwrite(bxInstruction_c *i) {
    unsigned encoding = BX_CPU(id)->gen_reg[i->dst()].dword.erx;
    return false;
}

static uint64_t auto_vmread(Bit32u encoding){
    switch ((encoding >> 13) & 0x3) {
        case 0:
            return BX_CPU(id)->VMread16(encoding);
            break;
        case 1:
        case 3:
            return BX_CPU(id)->VMread64(encoding);
            break;
        case 2:
            return BX_CPU(id)->VMread32(encoding);
            break;
        default:
            abort();
            return 0 ;
    }
}

extern "C" void __sanitizer_print_stack_trace();

unsigned fuzz_get_vmcs_field_offset(Bit32u encoding) {
    static int reenter; 
    if(cpu0_get_fuzztrace() && !reenter){
        reenter = 1;
        printf("VMCS->%lx = VMCS[%lx] = %lx\n", encoding, shadow_vmcs_layout[encoding], auto_vmread(encoding));
        reenter = 0;
    }
    return shadow_vmcs_layout[encoding];
}

extern bool fuzz_timeout;

/*
 * We want identity paging. 4k granularity for the first pages (where we will
 * place the code). 1G for everything else.
 *
 * 0x0                                      0xffffffffffffffff
 * [CODE] [       ] [       ] [       ] ....
 */
void redo_paging() {
    bx_address pml4_addr, pdpt_addr, pd_addr, pt_addr, code_addr;
    bx_address pml4 = 0 , pdpt = 0, pd = 0, pt = 0, code = 0;
    assert(guest_page_scratchlist.size() >= 10);
    pml4_addr = guest_page_scratchlist[0];
    pdpt_addr = guest_page_scratchlist[1];
    pd_addr = guest_page_scratchlist[2];
    pt_addr = guest_page_scratchlist[3];
    code_addr = guest_page_scratchlist[9];
    BX_CPU(id)->VMwrite64(VMCS_GUEST_CR3, pml4_addr);
    BX_CPU(id)->VMwrite64(VMCS_GUEST_RIP, code_addr);
    
    printf("USING %lx for PML4 and %lx for PDPT and %lx for PD and %lx for PT and %lx for CODE\n", pml4_addr, pdpt_addr, pd_addr, pt_addr, code_addr);

    // Set up identity mapping in the guest
    int res = BX_CPU(id)->dbg_translate_guest_physical_ept(pml4_addr, &pml4, 1);
    assert(pml4);
    res = BX_CPU(id)->dbg_translate_guest_physical_ept(pdpt_addr, &pdpt, 1);
    assert(pdpt);
    res = BX_CPU(id)->dbg_translate_guest_physical_ept(pd_addr, &pd, 1);
    assert(pd);
    res = BX_CPU(id)->dbg_translate_guest_physical_ept(pt_addr, &pt, 1);
    assert(pt);
    res = BX_CPU(id)->dbg_translate_guest_physical_ept(code_addr, &code, 1);
    assert(code);



    // Map the first 2MB of memory using 4k pages
    uint64_t entry = (pdpt_addr | 0x3);
    cpu_physical_memory_write_fastpath(pml4, &entry, sizeof(entry));
    entry = (pd_addr | 0x3);
    cpu_physical_memory_write_fastpath(pdpt, &entry, sizeof(entry));
    entry = (pt_addr | 0x3);
    cpu_physical_memory_write_fastpath(pd, &entry, sizeof(entry));
    /* uint64_t entry = (code_addr | 0xc3); */
    /* cpu_physical_memory_write_fastpath(pd, &entry, sizeof(entry)); */

    for (int i=1; i<512; i++) {
        entry = 0x40000000*i + 0x83;
        cpu_physical_memory_write_fastpath(pdpt + i*sizeof(entry), &entry, sizeof(entry));
    }
    for (int i=1; i<512; i++) {
        entry = 0x200000*i + 0x83;
        cpu_physical_memory_write_fastpath(pd + i*sizeof(entry), &entry, sizeof(entry));
    }
    for (int i=0; i<512; i++) {
        entry = 0x1000*i + 0xc3;
        cpu_physical_memory_write_fastpath(pt + i*sizeof(entry), &entry, sizeof(entry));
    }

    if(!fuzzing) {
        uint64_t phy;
        if(!gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy)){
            fflush(stdout);
            printf("failed to redo paging\n");
            abort();
        }
    }
}
// setup identity mapping for guest page table in the emulator
// i.e. GVA == HVA, for ease of debugging
void vmcs_fixup() {
    // Set program counter

    BX_CPU(id)->VMwrite32(VMCS_32BIT_IDT_VECTORING_INFO, 0);
   
    BX_CPU(id)->VMwrite64(VMCS_GUEST_RFLAGS, 0);
    BX_CPU(id)->VMwrite32(VMCS_32BIT_GUEST_SS_ACCESS_RIGHTS, 0);

    BX_CPU(id)->VMwrite64(VMCS_64BIT_GUEST_IA32_EFER, 0x500);

    redo_paging();
    // TODO: Need to make sure the gaddr is associated with a valid EPT entry.
    return;
}

#define VMCS12_IDX_TO_ENC(idx) ((uint16_t)(((uint16_t)(idx) >> 6) | ((uint16_t)(idx) << 10)))
void icp_init_shadow_vmcs_layout(const char* filename) {
    std::ifstream file(filename);
    std::string str; 
    std::stringstream ss;
    std::regex reg_regex("encoding (\\w+) at (\\w+)"); 
    printf(".loading shadow vmcs offsets from %s\n", filename);
    while (std::getline(file, str))
    {
        std::smatch match; 
        std::regex_search(str, match, reg_regex);
        if(match.size() < 1){
            continue;
        }
        uint64_t encoding;
        uint64_t offset;
        ss << std::hex << match[1].str(); 
        ss >> encoding;
        ss.clear();
        ss << std::hex << match[2].str(); 
        ss >> offset;
        ss.clear();
        shadow_vmcs_layout[encoding] = offset;
    }
}
