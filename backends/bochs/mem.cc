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
#include "fuzz.h"
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

BOCHSAPI BX_MEM_C bx_mem;

void cpu0_read_virtual(hp_address start, size_t size, void *data) {
  BX_CPU(0)->access_read_linear(start, size, 0, BX_READ, 0x0, data);
}

void cpu0_write_virtual(hp_address start, size_t size, void *data) {
  BX_CPU(0)->access_write_linear(start, size, 0, BX_WRITE, 0x0, data);
}

bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf) {
  bx_phy_address phy_addr;
  /* BX_CPU(0)->access_read_linear(pc&(~0xFFFLL), 0x1000, 0, BX_READ, 0x0, instr_buf); */
  bool valid = BX_CPU(0)->dbg_xlate_linear2phy(pc&(~0xFFFLL), &phy_addr);
  if (valid) {
    BX_MEM(0)->dbg_fetch_mem(BX_CPU_THIS, phy_addr, 4096, instr_buf);
    return true;
  } else
    return false;
}

bx_phy_address cpu0_virt2phy(bx_address start) {
  Bit32u lpf_mask = 0xfff; // 4K pages
  Bit32u pkey = 0;
  bx_phy_address phystart = BX_CPU(0)->translate_linear_long_mode(start, lpf_mask, pkey, 0, BX_READ);
  return phystart;
}

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) {
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void *)buf);
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
	BX_MEM(0)->readPhysicalPage(BX_CPU(id), addr, len, buf);
}

void cpu0_tlb_flush(void) {
	BX_CPU(id)->TLB_flush();
}
