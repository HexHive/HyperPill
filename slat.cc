#include "fuzz.h"

uint64_t pow64(uint64_t x, uint64_t y){
    uint64_t result = 1;
    while(y--){
        result*=x;
    }
    return result;
}

void enum_handle_slat_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end) {
#if defined(HP_X86_64)
    enum_handle_ept_gap(gap_reason, gap_start, gap_end);
#elif defined(HP_AARCH64)
    enum_handle_s2pt_gap(gap_reason, gap_start, gap_end);
#endif
}

std::vector<size_t> guest_page_scratchlist; /* a list of pages that we can use for our purposes */

void walk_slat(){
    uint64_t addr = 0;
    uint64_t phy = 0;
    int reason;
    int translation_level;
    size_t size;

    uint64_t gap_start = 0;
    int gap_reason = 0;

    do {
        phy = 0;
        reason = gpa2hpa(addr, &phy, &translation_level);
        size = 0x1000*pow64(512, translation_level);
        if(phy){
            verbose_printf("0x%016lx 0x%016lx 0x%08lx (0x%016lx)\n", addr, phy, size, guest_mem_size);
            mark_l2_guest_page(phy, size, addr);
            if(guest_page_scratchlist.size() < 10) {
                guest_page_scratchlist.push_back(addr);
            }
        }

        if(reason != gap_reason){
            if(gap_reason)
                enum_handle_slat_gap(gap_reason, gap_start, addr-1);
            gap_reason = reason;
            gap_start = addr;
        }

        addr += size;
        addr &= (~(pow64(512, translation_level)-1));
#if defined(HP_X86_64)
    } while(addr!=0 && addr < 0x1000*pow64(512, 4));
#elif defined(HP_AARCH64)
    } while(addr!=0 && addr < 0x1000*pow64(512, 3));
#endif
    if(gap_reason)
        enum_handle_slat_gap(gap_reason, gap_start, addr-1);
}

void fuzz_walk_slat() {
    printf(".performing slat walk \n");

    // We walk the ept for 2 reasons:
    // 1. To identify L0 Pages that are allocated to L1. We want this info so we
    // can detect DMA-Style reads from L1's memory.
    /* Our memory snapshot contains the hypervisor and the VM it is running */
    /* (called L2). At some point the hypervisor might try to read/write from */
    /* the VM's memory (e.g. DMA virtual devices). We want to be able to hook */
    /* those memory-accesses so to do that let's identify all of the pages in */
    /* the snapshot that are dedicated to L2. To do that we can walk the EPT */
    /* that was set up by the hypervisor for L2, which gives a mapping of */
    /* guest-physical to host-physical addresses. */
    // 2. To enumerate potential MMIO Ranges.
    guest_mem_size = 0;
    walk_slat();
    /* walk_ept_kvm(BX_LEVEL_PML4, pml4_gpa, 0); */
    printf("Total Identified L2 Pages: %lx\n", guest_mem_size);
}

void slat_locate_pc() {
#if defined(HP_X86_64)
    ept_locate_pc();
#elif defined(HP_AARCH64)
    s2pt_locate_pc();
#endif
}

void slat_mark_page_table() {
#if defined(HP_X86_64)
    ept_mark_page_table();
#elif defined(HP_AARCH64)
    s2pt_mark_page_table();
#endif
}
