#include "fuzz.h"

#include <tsl/robin_set.h>
#include <tsl/robin_map.h>

size_t maxaddr = 0;

uint8_t* is_l2_page_bitmap; /* Page is in L2 */
uint8_t* is_l2_pagetable_bitmap; /* Page is in L2 */
size_t guest_mem_size;

tsl::robin_map<hp_phy_address, hp_phy_address> persist_ranges;
tsl::robin_map<hp_phy_address, hp_phy_address> hpa_to_gpa;

std::vector<std::tuple<hp_address, uint8_t, uint8_t>> fuzzed_guest_pages; // < HPA, pagetable_level, original_val >

uint64_t lookup_gpa_by_hpa(uint64_t hpa){
    uint64_t page = hpa;
    uint64_t offset;
    int i = 0;
    while (hpa_to_gpa.find(page) == hpa_to_gpa.end() && page){
        i++;
        page = ((page >> i) << i);
    }
    if(!page)
        printf("Error looking up GPA for HPA: %lx\n", hpa);
    return hpa_to_gpa[page] | (hpa&(~(((uint64_t)(-1)>>i)<<i)));
}
/**
 * During fuzzing, there is a chance that new guest addresses get paged in.
 * The corresponding HPAs have not been marked as guest pages, so we mark them.
 * However, the EPT is reset across fuzz iterations, so have to unmark
 * the pages that have been marked during the current fuzz iteration
*/
#define PG_PRESENT_BIT  0
#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
void fuzz_mark_l2_guest_page(uint64_t paddr, uint64_t len) {
    uint64_t pg_entry;
    cpu0_mem_read_physical_page(paddr, sizeof(pg_entry), &pg_entry);
#if defined(HP_X86_64)
    hp_phy_address new_addr = pg_entry & 0x3fffffffff000ULL;
#endif
    uint8_t new_pgtable_lvl = is_l2_pagetable_bitmap[paddr >> 12] - 1;
    uint8_t pg_present_or_valid = pg_entry & PG_PRESENT_MASK;

    if (!pg_present_or_valid || new_addr >= maxaddr)
      return;

    // store all updates made for the current fuzzing iteration
    fuzzed_guest_pages.push_back(std::make_tuple(new_addr, new_pgtable_lvl, is_l2_pagetable_bitmap[new_addr>>12]));
    //printf("!fuzz_mark_l2_guest_page Mark 0x%lx lvl %x as tmp guest page\n", new_addr, new_pgtable_lvl);
    if (new_pgtable_lvl) {
        mark_l2_guest_pagetable(new_addr, len, new_pgtable_lvl - 1);
    } else {
        mark_l2_guest_page(new_addr, len, 0);
    }
}

void fuzz_reset_watched_pages() {
    // printf("[fuzz_reset_watched_pages] reset 0x%lx watched pages\n", fuzzed_guest_pages.size());;
    for (auto& page : fuzzed_guest_pages) {
      hp_address addr = std::get<0>(page);
      uint8_t is_pgtable = std::get<1>(page);
      uint8_t saved_val = std::get<2>(page);
      if (is_pgtable)
        is_l2_pagetable_bitmap[addr >> 12] = saved_val;
      else // normal guest page
        is_l2_page_bitmap[addr >> 12] = saved_val;
    }
    fuzzed_guest_pages.clear();
}

void add_persistent_memory_range(hp_phy_address start, hp_phy_address len) {
    /* printf("Add persistent memory range: %lx %lx\n", start, len); */
    hp_phy_address page = (start >> 12) << 12;
    hp_phy_address startend;
    assert(((start+len-1)>>12) == (page >> 12));

    startend = start-page;
    startend |= (start+len - page) << 12;
    persist_ranges[page] = startend;
}

void mark_page_not_guest(hp_phy_address addr, int level) {
    is_l2_page_bitmap[addr>>12] = 0;
}

bool frame_is_guest(hp_phy_address addr) {
    return is_l2_page_bitmap[addr>>12] ;
}

void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr){
    hpa_to_gpa[paddr] = addr;
    while(paddr < maxaddr && len) {
        is_l2_page_bitmap[paddr>>12]++;
        len -= 0x1000;
        paddr += 0x1000;
        guest_mem_size += 0x1000;
    }
}

void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level) {
    if(paddr < maxaddr) {
        // we use page level values of >=1 to facilitate checking the bitmap
        // bitmap value of 0 will indicate that the page is not present
        // a non-zero bitmap value will indicate the page level, with
        // level 1 mapped to BX_LEVEL_PTE and level 4 mapped to BX_LEVEL_PML4
        is_l2_pagetable_bitmap[paddr>>12] = level + 1;
        assert(level >= 0 && level <= 3);
    }
}

// c bingings for fuzzed_guest_pages
void fuzzed_guest_paged_push_back(uint64_t hpa, uint8_t pagetable_level, uint8_t original_val) {
    fuzzed_guest_pages.push_back(std::make_tuple(hpa, pagetable_level, original_val));
}
