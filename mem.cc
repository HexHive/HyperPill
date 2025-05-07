#include "fuzz.h"

#include <tsl/robin_set.h>
#include <tsl/robin_map.h>

size_t maxaddr = 0;

uint8_t* is_l2_page_bitmap; /* Page is in L2 */
uint8_t* is_l2_pagetable_bitmap; /* Page is in L2 */
size_t guest_mem_size;

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

void mark_page_not_guest(hp_phy_address addr, int level) {
    printf("Mark page not present: %lx\n", addr);
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

// c bindings for hpa_to_gpa
void hpa_to_gpa_get(uint64_t hpa, uint64_t *gpa) {
  *gpa = hpa_to_gpa[hpa];
}

void hpa_to_gpa_set(uint64_t hpa, uint64_t *gpa) {
  hpa_to_gpa[hpa] = *gpa;
}

// c bingings for fuzzed_guest_pages
void fuzzed_guest_paged_push_back(uint64_t hpa, uint8_t pagetable_level, uint8_t original_val) {
    fuzzed_guest_pages.push_back(std::make_tuple(hpa, pagetable_level, original_val));
}
