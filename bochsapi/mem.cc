#include <sys/mman.h>
#include <cstdint>

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>


#include <tsl/robin_set.h>
#include <tsl/robin_map.h>
#include "../fuzz.h"
#include <openssl/md5.h>

BX_MEM_C::BX_MEM_C() {}
BX_MEM_C::~BX_MEM_C() {}

size_t maxaddr = 0;

static uint8_t watch_level = 0;
static uint8_t* overlays[3];
uint8_t* is_l2_page_bitmap; /* Page is in L2 */
uint8_t* is_l2_pagetable_bitmap; /* Page is in L2 */
size_t guest_mem_size;

int shfd; // for overlay[0]
char md5sum_chr[33]; // for overlay[0]
int shm_open(const char *name, int oflag, mode_t mode);


uint8_t *cow_bitmap;
uint8_t *overlay_map; // 0: from shadowmem 1: from workershadowmem

tsl::robin_set<bx_phy_address> dirtyset;

tsl::robin_map<bx_phy_address, bx_phy_address> persist_ranges;
tsl::robin_map<bx_phy_address, bx_phy_address> hpa_to_gpa;

std::vector<std::tuple<bx_address, uint8_t, uint8_t>> fuzzed_guest_pages; // < HPA, pagetable_level, original_val >

static int memory_commit_level;

size_t ndirty=0;

static bx_address prioraccess;
void fuzz_hook_memory_access(bx_address phy, unsigned len, 
                             unsigned memtype, unsigned rw, void* data) {
    bx_address aligned = phy&(~0xFFFLL);

    /* printf("Memory access to %lx\n", phy); */
    // Sometimes we might run instructions during initialization and we
    // want them to be part of the snapshot.
    if(watch_level<=1 || phy >= maxaddr)
        return;

    if(aligned == prioraccess)
        return;

    if(rw == BX_WRITE || rw == BX_RW) {
        prioraccess = aligned;
      // This stores the addr in the dirtyset (reset for each input) and makes a
      // copy of the corresponding page in shadowset/shadowmem (persistent).
      // Otherwise I run out of RAM on my machine :')
      // When we do the actual fuzzing runs on beefier hardware, we should just
      // make a complete shadow-copy on startup.
      if (dirtyset.emplace(aligned).second) {
          if(ndirty++>10000){
              printf("Too many dirty pages. Early stop\n");
              fuzz_emu_stop_unhealthy();
          }
      }
    }

    // used to identify DMA accesses in the guest
    // contains a mapping for each host physical page, for whether it corresponds to a guest page
    // if an access uses such an address, it is likely a DMA
    if (rw == BX_READ && is_l2_page_bitmap[phy >> 12]) {
        if(cpu0_get_fuzztrace()) {
            /* printf(".dma inject: %lx +%lx ",phy, len); */
        }
        static void* hv = getenv("HYPERV");
        if(BX_CPU(0)->user_pl || hv)
            fuzz_dma_read_cb(phy, len, data);
      uint8_t data[len];
      BX_MEM_C::readPhysicalPage(BX_CPU(id), phy, len, data);
      prioraccess = -1;
    }
}

void fuzz_clear_dirty() {
    ndirty = 0;
    dirtyset.clear();
}

void fuzz_watch_memory_inc() {
    watch_level++;
}


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
void fuzz_mark_l2_guest_page(uint64_t paddr, uint64_t len) {
    uint64_t pg_entry;
    cpu_physical_memory_read(paddr, &pg_entry, sizeof(pg_entry));
    bx_phy_address new_addr = pg_entry & 0x3fffffffff000ULL;
    uint8_t new_pgtable_lvl = is_l2_pagetable_bitmap[paddr >> 12] - 1;
    uint8_t pg_present = pg_entry & PG_PRESENT_MASK;

    if (!pg_present || new_addr >= maxaddr)
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
      bx_address addr = std::get<0>(page);
      uint8_t is_pgtable = std::get<1>(page);
      uint8_t saved_val = std::get<2>(page);
      if (is_pgtable)
        is_l2_pagetable_bitmap[addr >> 12] = saved_val;
      else // normal guest page
        is_l2_page_bitmap[addr >> 12] = saved_val;
    }
    fuzzed_guest_pages.clear();
}

void add_persistent_memory_range(bx_phy_address start, bx_phy_address len) {
    /* printf("Add persistent memory range: %lx %lx\n", start, len); */
    bx_phy_address page = (start >> 12) << 12;
    bx_phy_address startend;
    assert(((start+len-1)>>12) == (page >> 12));

    startend = start-page;
    startend |= (start+len - page) << 12;
    persist_ranges[page] = startend;
    
}

static void notify_write(uint64_t addr){
    size_t page = addr >> 12;
    size_t aligned_addr = page << 12;
    if(cow_bitmap[page] != watch_level) {
        cow_bitmap[page] = watch_level;
        memcpy(overlays[cow_bitmap[page]] + aligned_addr, overlays[overlay_map[page]]+aligned_addr, 0x1000);
        if(watch_level < 2){
            overlay_map[page] = watch_level;
        }
    }
    /* printf("Page %lx now lives at %lx and is backed by %lx\n", page, cow_bitmap[page], overlay_map[page]); */
}

uint8_t* addr_conv(uint64_t addr){
    /* printf("ADDR_CONV: %lx -> %lx [%d]\n", addr,overlays[cow_bitmap[addr>>12]]+addr, cow_bitmap[addr>>12]); */
    return overlays[cow_bitmap[addr>>12]]+addr;
}
uint8_t* backing_addr(uint64_t addr){
    return overlays[overlay_map[addr>>12]]+addr;
}

void fuzz_reset_memory() {
    if(watch_level<=1)
        return;
    prioraccess=0;
    for(const auto& key : dirtyset) {
        size_t page = key >> 12;
        if (persist_ranges.find(key) != persist_ranges.end()){
            bx_phy_address start = persist_ranges[key] & 0xFFF;
            bx_phy_address end = persist_ranges[key] >> 12;
            memcpy(addr_conv(key), backing_addr(key), start);
            memcpy(addr_conv(key+end), backing_addr(key+end), 0x1000-end);
        } else {
            memcpy(addr_conv(key), backing_addr(key), 0x1000);
        }
    }
    fuzz_clear_dirty();
    fuzz_reset_watched_pages();
}


void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
    unsigned len, void *data)
{

    notify_write(addr);
    fuzz_hook_memory_access(addr, len, 0, BX_WRITE, NULL) ;

    memcpy(addr_conv(addr), data, len);

    if (is_l2_pagetable_bitmap[addr >> 12] && watch_level > 1) {
      fuzz_mark_l2_guest_page(addr, 0x1000);
    }

    return;
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
    memcpy(data, addr_conv(addr), len);
    return;
}

void mark_page_not_guest(bx_phy_address addr, int level) {
    printf("Mark page not present: %lx\n", addr);
    is_l2_page_bitmap[addr>>12] = 0;
}

bool frame_is_guest(bx_phy_address addr) {
    return is_l2_page_bitmap[addr>>12] ;
}

Bit8u *BX_MEM_C::getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    if(rw!=BX_READ)
        notify_write(addr);
    return addr_conv(addr);
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf)
{
    readPhysicalPage(cpu, addr, len , buf);
    return true;
}

bool BX_MEM_C::dbg_set_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf)
{
    notify_write(addr);
    memcpy(addr_conv(addr), buf, len);
    return true;
}

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

void _shm_unlink(void) {
    if (shm_unlink(md5sum_chr) == -1) {
        perror("shm_unlink");
    } else {
        printf("shm '%s' has been unlinked.\n", md5sum_chr);
    }
    close(shfd);
}

void icp_init_mem(const char *filename) {
  // Either Elf64_Ehdr or Elf32_Ehdr depending on architecture.
  struct stat statbuf;
  ElfW(Ehdr) * ehdr;
  ElfW(Phdr) *phdr = 0;
  ElfW(Nhdr) *nhdr = 0;
  unsigned char md5sum_hex[MD5_DIGEST_LENGTH];

  FILE *file = fopen(filename, "rb");
  if (file) {
    fstat(fileno(file), &statbuf);

    ehdr = (ElfW(Ehdr) *)mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fileno(file), 0);

    phdr = (ElfW(Phdr) *)(ehdr->e_phoff + (size_t)ehdr);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdr->p_vaddr + phdr->p_memsz > maxaddr && phdr->p_type == 1) {
        maxaddr = phdr->p_vaddr + phdr->p_memsz;
      }
      ++phdr;
    }
    verbose_printf("Max Addr: %lx\n", maxaddr);
    assert(maxaddr % 4096 == 0);

    // Now that we know how much memory we need, do THREE mmaps:
    // 3 layers 3 mmaps
    // The first layer is shadowmem: this will contain the verbatim contents of the snapshot. This is mmapped from a shared file which is shared by all the workers. It is mapped read-only and should never be changed
    // The second layer is workershadowmem: this is the per-worker memory that differs from shadowmem (i.e. dirtied by writes) but which should be persisted between writes
    // The third layer is mem: this is the per-worker dirty memory which is used during fuzzing and should be reset after each input
    overlays[2] = (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    overlays[1]= (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    char *saved_md5sum_chr = getenv("ICP_MEM_MD5SUM");
    if (saved_md5sum_chr) {
        memcpy(md5sum_chr, saved_md5sum_chr, 32);
    } else {
        MD5((unsigned char*)ehdr, statbuf.st_size, md5sum_hex);
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            sprintf(md5sum_chr + (i * 2), "%02x", md5sum_hex[i]);
        }
    }
    md5sum_chr[32] = '\0';
    shfd = shm_open((const char*)md5sum_chr, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    
    if(lseek(shfd, 0L, SEEK_END) == 0){
        lseek(shfd, 0L, SEEK_SET);
        ftruncate(shfd, maxaddr);
        overlays[0]= (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                MAP_SHARED, shfd, 0);

        phdr = (ElfW(Phdr) *)(ehdr->e_phoff + (size_t)ehdr);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr->p_type == 1) {
                memcpy(overlays[0] + phdr->p_vaddr, (uint8_t *)ehdr + phdr->p_offset,
                        phdr->p_filesz);
            }
            ++phdr;
        }
    } else {
        lseek(shfd, 0L, SEEK_SET);
        overlays[0] = (uint8_t *)mmap(NULL, maxaddr, PROT_READ|PROT_WRITE,
                MAP_SHARED, shfd, 0);
    }

    cow_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(cow_bitmap, 0, maxaddr >> 12);
    
    overlay_map = (uint8_t *)malloc(maxaddr >> 12);
    memset(overlay_map, 0, maxaddr >> 12);

    is_l2_page_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(is_l2_page_bitmap, 0, maxaddr >> 12);

    is_l2_pagetable_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(is_l2_pagetable_bitmap, 0, maxaddr >> 12);

    munmap(ehdr, statbuf.st_size);
    // finally close the file
    fclose(file);

  }
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

void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len){
    memcpy(dest, addr_conv(addr), len);
}

void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len){
    notify_write(addr);
    memcpy(addr_conv(addr), src, len);
}

BOCHSAPI BX_MEM_C bx_mem;

void cpu0_mem_write_physical_page(bx_phy_address addr, size_t len, void *buf) {
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void *)buf);
}

void cpu0_mem_read_physical_page(bx_phy_address addr, size_t len, void *buf) {
	BX_MEM(0)->readPhysicalPage(BX_CPU(id), addr, len, buf);
}