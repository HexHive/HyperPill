#include "config.h"
#include "fuzz.h"
#include <asm-generic/errno.h>
#include <math.h>

const Bit64u BX_PAGING_PHY_ADDRESS_RESERVED_BITS = BX_PHY_ADDRESS_RESERVED_BITS & BX_CONST64(0xfffffffffffff);
const Bit64u PAGING_EPT_RESERVED_BITS = BX_PAGING_PHY_ADDRESS_RESERVED_BITS;                                  

static uint64_t pow64(uint64_t x, uint64_t y){
    uint64_t result = 1;
    while(y--){
        result*=x;
    }
    return result;
}
void walk_ept(){
    uint64_t addr = 0;
    uint64_t phy = 0;
    int reason;
    int translation_level;

    uint64_t gap_start = 0;
    int gap_reason = 0;

    do {
        phy = 0;
        reason = vmcs_translate_guest_physical_ept(addr, &phy, &translation_level);
        if(phy){
            mark_l2_guest_page(phy, 0x1000*pow64(512, translation_level), addr);
            if(guest_page_scratchlist.size() < 10) {
                guest_page_scratchlist.push_back(addr);
            }
        }

        if(reason != gap_reason){
            if(gap_reason)
                enum_handle_ept_gap(gap_reason, gap_start, addr-1);
            gap_reason = reason;
            gap_start = addr;
        }

        addr += 0x1000*pow64(512, translation_level);
        addr &= (~(pow64(512, translation_level)-1));
    } while(addr!=0 && addr < 0x1000*pow64(512, 4));
    if(gap_reason)
        enum_handle_ept_gap(gap_reason, gap_start, addr-1);
}


extern size_t guest_mem_size;
void fuzz_walk_ept() {
    printf(".performing ept walk \n");
    uint64_t eptp = BX_CPU(id)->VMread64(VMCS_64BIT_CONTROL_EPTPTR);
    printf("EPTP: %lx\n", eptp);
    /* printf("EPT Paging Structure Memory Type: %lx\n", eptp&0b111); */
    /* printf("EPT Page Walk Length: %lx\n", ((eptp>>3)&0b111) + 1); */
    /* printf("EPT Dirty Flags Enabled: %lx\n", (eptp>>6)&0b1); */
    /* printf("EPT Enforce access rights for supervisor shadow-stack pages: %lx\n", (eptp>>7)&0b1); */
    uint64_t pml4_gpa = (eptp)&(~0xFFF);
    /* printf("EPT PML4 Pointer: %lx\n", pml4_gpa); */

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
    walk_ept();
    /* walk_ept_kvm(BX_LEVEL_PML4, pml4_gpa, 0); */
    printf("Total Identified L2 Pages: %lx\n", guest_mem_size);
}

int vmcs_translate_guest_physical_ept(bx_phy_address guest_paddr, bx_phy_address *phy, int *translation_level)
{
  VMCS_CACHE *vm = &BX_CPU(id)->vmcs;
  bx_phy_address pt_address = LPFOf(vm->eptptr) ;//BX_CPU(id)->VMread64(VMCS_64BIT_CONTROL_EPTPTR) & (~0xFFF);

  Bit64u offset_mask = BX_CONST64(0x0000ffffffffffff);
  for (int level = 3; level >= 0; --level) {
    if(translation_level)
        *translation_level = level;
    Bit64u pte;
    pt_address += ((guest_paddr >> (9 + 9*level)) & 0xff8);
    offset_mask >>= 9;
    mark_l2_guest_pagetable(pt_address, 0x1000, level);
    BX_MEM(0)->readPhysicalPage(BX_CPU_THIS, pt_address, 8, &pte);
    /* printf("guest_paddr: %lx pte[%lx]: %lx\n", guest_paddr, pt_address, pte); */
    switch(pte & 7) {
    case BX_EPT_ENTRY_NOT_PRESENT:
      return VMX_VMEXIT_EPT_VIOLATION;
    case BX_EPT_ENTRY_WRITE_ONLY:
    case BX_EPT_ENTRY_WRITE_EXECUTE:
      return VMX_VMEXIT_EPT_MISCONFIGURATION;
    }

    extern bool isMemTypeValidMTRR(unsigned memtype);
    if (! isMemTypeValidMTRR((pte >> 3) & 7)) {
      return VMX_VMEXIT_EPT_MISCONFIGURATION;
    }
    
    if (pte & BX_PAGING_PHY_ADDRESS_RESERVED_BITS)
      return VMX_VMEXIT_EPT_MISCONFIGURATION;

    pt_address = bx_phy_address(pte & BX_CONST64(0x000ffffffffff000));

    if (level == BX_LEVEL_PTE) break;

    if (pte & 0x80) {
        if (level > (BX_LEVEL_PDE + !!BX_CPU(id)->is_cpu_extension_supported(BX_ISA_1G_PAGES)))
            return VMX_VMEXIT_EPT_MISCONFIGURATION;

        pt_address &= BX_CONST64(0x000fffffffffe000);
        if (pt_address & offset_mask) return VMX_VMEXIT_EPT_MISCONFIGURATION;
        break;
    }
    if ((pte >> 3) & 0xf) {
      return VMX_VMEXIT_EPT_MISCONFIGURATION;
    }
  }
  if(phy)
    *phy = pt_address + (bx_phy_address)(guest_paddr & offset_mask);
  return 0;
}

// Translate GVA -> GPA -> HPA
bool vmcs_linear2phy(bx_address laddr, bx_phy_address *phy)
{
  bx_phy_address paddress;
  bx_address offset_mask = 0xfff;

  uint64_t cr0 = BX_CPU(id)->VMread64(VMCS_GUEST_CR0);
  uint64_t cr3 = BX_CPU(id)->VMread64(VMCS_GUEST_CR3);
  uint64_t cr4 = BX_CPU(id)->VMread64(VMCS_GUEST_CR4);
  uint64_t efer = BX_CPU(id)->VMread64(VMCS_64BIT_GUEST_IA32_EFER);

  int long_mode = (efer  >> 10) &1;
  if (!((cr0 >> 31) & 1)) { // get_PG
    paddress = (bx_phy_address) laddr;
  }
  else {
    // walk guest page table: GVA -> GPA
    bx_phy_address pt_address = cr3 & BX_CONST64(0x000ffffffffff000);

    if ((cr4 >> 5)&1) { // get_PAE
      offset_mask = BX_CONST64(0x0000ffffffffffff);

      int level = 3;
      if (! long_mode) {
        goto page_fault;
      }

      for (; level >= 0; --level) {
        Bit64u pte;
        pt_address += ((laddr >> (9 + 9*level)) & 0xff8);
        offset_mask >>= 9;
        if (vmcs_translate_guest_physical_ept(pt_address, &pt_address, NULL))
            goto page_fault;
        BX_MEM(0)->readPhysicalPage(BX_CPU(id), pt_address, 8, &pte);
        if(!(pte & 1))
          goto page_fault;
        if (pte & BX_PAGING_PHY_ADDRESS_RESERVED_BITS)
          goto page_fault;
        pt_address = bx_phy_address(pte & BX_CONST64(0x000ffffffffff000));
        if (level == BX_LEVEL_PTE) break;
        if (pte & 0x80) {
          // large page
          pt_address &= BX_CONST64(0x000fffffffffe000);
          if (pt_address & offset_mask)
            goto page_fault;
          if (BX_CPU(id)->is_cpu_extension_supported(BX_ISA_1G_PAGES) && level == BX_LEVEL_PDPTE) break;
          if (level == BX_LEVEL_PDE) break;
          goto page_fault;
        }
      }
      paddress = pt_address + (bx_phy_address)(laddr & offset_mask);
    }
    else   // not PAE
    {
        abort();
    }
  }
  if (vmcs_translate_guest_physical_ept(paddress, &paddress, NULL))
      goto page_fault;
  *phy = paddress;
  return 1;
page_fault:
  printf("PAGE FAULT ON ADDR: %lx\n", paddress);
  return 0;
}


void ept_locate_pc() {
    bx_address phyaddr;
    vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phyaddr);
    printf("%lx -> %lx\n", BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phyaddr);
    
    vmcs_linear2phy(0, &phyaddr);
    printf("%lx -> %lx\n", 0, phyaddr);
}

// Walk guest page table
void iterate_page_table(int level, bx_phy_address pt_address) {
    printf("Page table %d at: %lx\n", level, pt_address);
    bx_phy_address translated_pt_address;
    vmcs_translate_guest_physical_ept(pt_address, &translated_pt_address, NULL);
    mark_page_not_guest(translated_pt_address, BX_LEVEL_PTE);
    for(int i=0; i<512 && level!=BX_LEVEL_PTE; i++) {
        Bit64u pte;
        vmcs_translate_guest_physical_ept(pt_address + i*8, &translated_pt_address, NULL);
        BX_MEM(0)->readPhysicalPage(BX_CPU(id), translated_pt_address, 8, &pte);
        printf("PTE: %lx\n", pte);
        if(level != BX_LEVEL_PTE && !(pte & 0x80)) {
            iterate_page_table(level -= 1, 
                    bx_phy_address(pte & BX_CONST64(0x000ffffffffff000)));
        }
    }
}

static void print_pte(bx_phy_address addr, bx_phy_address pte, bx_phy_address mask)
{
    if (addr & (1ULL << 47)) {
        addr |= (bx_phy_address)-(1LL << 48);
    }

    printf("%lx: %lx"
                   " %c%c%c%c%c%c%c%c%c %c\n",
                   addr,
                   pte & mask,
                   pte & PG_NX_MASK ? 'X' : '-',
                   pte & PG_GLOBAL_MASK ? 'G' : '-',
                   pte & PG_PSE_MASK ? 'P' : '-',
                   pte & PG_DIRTY_MASK ? 'D' : '-',
                   pte & PG_ACCESSED_MASK ? 'A' : '-',
                   pte & PG_PCD_MASK ? 'C' : '-',
                   pte & PG_PWT_MASK ? 'T' : '-',
                   pte & PG_USER_MASK ? 'U' : '-',
                   pte & PG_RW_MASK ? 'W' : '-',
                   frame_is_guest(pte&mask) ? 'g' : '-'
                   );
}

static void page_walk_la48(uint64_t pml4_addr,
    bool guest, // Translate guest addresses to host (are we walking the guest's page table ?)
    void (*page_table_cb)(bx_phy_address address, int level), // cb for each frame that belongs to the page-table tree
    void (*leaf_pte_cb)(bx_phy_address addr, bx_phy_address pte, bx_phy_address mask) // cb for each leaf pte
    )
{
    printf("Walking page table at %lx\n", pml4_addr);
    uint64_t l0 = 0;
    uint64_t l1, l2, l3, l4;
    uint64_t pml4e, pdpe, pde, pte;
    uint64_t pdp_addr, pd_addr, pt_addr;
    uint64_t physical_pt_address;

    uint64_t prior1, prior2, prior3, prior4;
    prior1 = 0;
    for (l1 = 0; l1 < 512; l1++) {
        if (guest)
            vmcs_translate_guest_physical_ept(pml4_addr + l1 * 8, &physical_pt_address, NULL);
        else 
            physical_pt_address = pml4_addr + l1 * 8;
        if (l1 == 0 && page_table_cb) {
            page_table_cb(physical_pt_address, BX_LEVEL_PML4);
        }
        BX_MEM(0)->readPhysicalPage(BX_CPU(id), physical_pt_address, 8, &pml4e);
        if (!(pml4e & PG_PRESENT_MASK)) {
            continue;
        }

        if(prior1 == pml4e)
            continue;
        prior1 = pml4e;

        pdp_addr = pml4e & 0x3fffffffff000ULL;
        prior2=0;
        for (l2 = 0; l2 < 512; l2++) {
            if (guest)
                vmcs_translate_guest_physical_ept(pdp_addr + l2 * 8, &physical_pt_address, NULL);
            else 
                physical_pt_address = pdp_addr + l2 * 8;
            if (l2 == 0 && page_table_cb) {
                page_table_cb(physical_pt_address, BX_LEVEL_PDPTE);
            }
            BX_MEM(0)->readPhysicalPage(BX_CPU(id), physical_pt_address, 8, &pdpe);
            if (!(pdpe & PG_PRESENT_MASK)) {
                continue;
            }

            if(prior2 == pdpe)
                continue;
            prior2 = pdpe;

            if (pdpe & PG_PSE_MASK) {
                /* 1G pages, CR4.PSE is ignored */
                if(leaf_pte_cb)
                    leaf_pte_cb((l0 << 48) + (l1 << 39) + (l2 << 30),
                            pdpe, 0x3ffffc0000000ULL);
                continue;
            }

            pd_addr = pdpe & 0x3fffffffff000ULL;
            prior3=0;
            for (l3 = 0; l3 < 512; l3++) {
                if (guest)
                    vmcs_translate_guest_physical_ept(pd_addr + l3 * 8, &physical_pt_address, NULL);
                else 
                    physical_pt_address = pd_addr + l3 * 8;
                if (l3 == 0 && page_table_cb) {
                    page_table_cb(physical_pt_address, BX_LEVEL_PDE);
                }
                BX_MEM(0)->readPhysicalPage(BX_CPU(id), physical_pt_address, 8, &pde);
                if (!(pde & PG_PRESENT_MASK)) {
                    continue;
                }

                if(prior3 == pde)
                    continue;
                prior3 = pde;

                if (pde & PG_PSE_MASK) {
                    /* 2M pages, CR4.PSE is ignored */
                    if(leaf_pte_cb)
                        leaf_pte_cb((l0 << 48) + (l1 << 39) + (l2 << 30) +
                                (l3 << 21), pde, 0x3ffffffe00000ULL);
                    continue;
                }

                pt_addr = pde & 0x3fffffffff000ULL;
                for (l4 = 0; l4 < 512; l4++) {
                    if (guest)
                        vmcs_translate_guest_physical_ept(pt_addr + l4 * 8, &physical_pt_address, NULL);
                    else 
                        physical_pt_address = pt_addr + l4 * 8;
                    if (l4 == 0 && page_table_cb) {
                        page_table_cb(physical_pt_address, BX_LEVEL_PTE);
                    }
                    BX_MEM(0)->readPhysicalPage(BX_CPU(id), physical_pt_address, 8, &pte);
                    if (pte & PG_PRESENT_MASK) {
                        if(leaf_pte_cb)
                            leaf_pte_cb((l0 << 48) + (l1 << 39) +
                                    (l2 << 30) + (l3 << 21) + (l4 << 12),
                                    pte & ~PG_PSE_MASK, 0x3fffffffff000ULL);
                    }
                }
            }
        }
    }
}

void ept_mark_page_table() {
    bx_address phyaddr;

    uint64_t cr3 = BX_CPU(id)->VMread64(VMCS_GUEST_CR3);
    bx_phy_address pt_address = cr3 & BX_CONST64(0x000ffffffffff000);
    page_walk_la48(pt_address, true, mark_page_not_guest, NULL);

    /* cr3 = BX_CPU(id)->cr3; */
    /* printf("WALKING CR3: %lx\n", cr3); */
    /* pt_address = cr3 & BX_CONST64(0x000ffffffffff000); */
    /* page_walk_la48(pt_address, false, NULL, print_pte); */

    // unmark the page containing the current guest RIP
    // alternatively, check that (addr != guest RIP) in the DMA hook
    if(vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phyaddr))
        mark_page_not_guest(phyaddr, BX_LEVEL_PTE);
    else {
        fprintf(stderr, "GUEST_RIP page not mapped");
        abort();
    }
}

static void print_page(bx_phy_address entry, int level, bx_phy_address virt ){
    uint64_t pte;
    return;
    for(int i=0; i<512; i++) {
        BX_MEM(0)->readPhysicalPage(BX_CPU(id), entry + i*8, 8, &pte);
        uint64_t final_virt = virt + ((uint64_t)i << (12 + (level*9)));
        if(pte & PG_PRESENT_MASK){
            printf("%lx: %d %lx[%d] %lx\n", final_virt, level, entry, i, pte);
        }
    }
}

void fuzz_walk_cr3() {
    bx_phy_address pt_address = BX_CPU(id)->cr3 & BX_CONST64(0x000ffffffffff000);
    pt_address  = BX_CPU(id)->VMread64(VMCS_GUEST_CR3) & 0x000ffffffffff000;
    page_walk_la48(pt_address, true, NULL, print_pte);
}
