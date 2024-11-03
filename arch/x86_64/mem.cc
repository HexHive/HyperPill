#include "fuzz.h"

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

extern void add_persistent_memory_range(bx_phy_address start, bx_phy_address len);

void hp_add_persistent_memory_range(hp_address start, size_t len) {
  Bit32u lpf_mask = 0xfff; // 4K pages
  Bit32u pkey = 0;
  bx_phy_address phystart = cpu0_virt2phy(start); 
  phystart = (phystart & ~((Bit64u) lpf_mask)) | (start & lpf_mask);
  add_persistent_memory_range(phystart, len);
}
