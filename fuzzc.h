#ifndef FUZZC_H
#define FUZZC_H

// backends/xxx/control
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void cpu0_run_loop();

// backends/xxx/mem
void cpu0_mem_read_physical_page(bx_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(bx_phy_address addr, size_t len, void *buf);

#endif
