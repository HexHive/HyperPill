#ifndef FUZZC_H
#define FUZZC_H

void cpu0_mem_read_physical_page(bx_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(bx_phy_address addr, size_t len, void *buf);

#endif
