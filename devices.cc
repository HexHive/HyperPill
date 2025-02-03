#include "bochs.h"
#include "fuzz.h"

#include "iodev/iodev.h"
#include "cpu/cpu.h"

bx_devices_c::bx_devices_c() {}
bx_devices_c::~bx_devices_c() {}

static char output_buf[128];
static char output_index = 0;

Bit32u bx_devices_c::inp(Bit16u addr, unsigned len) {
    if (addr == 0x3fd) {
        printf("%s\n", output_buf);
        memset(output_buf, 0, 128);
        output_index = 0;
        return 0x20;
    }
    printf("PIO READ ADDR: %x\n", addr);
    return 0;
    if (addr >= 0x3f8 && addr <= 0x3ff)
        return 0;
    if(addr == 0x608)
        return 0x00b05c69;
    return 0;
}
void bx_devices_c::outp(Bit16u addr, Bit32u value, unsigned len) { 
    if (addr == 0x3f8) {
        output_buf[output_index % 128] = (unsigned char)value;
        output_index++;
        return;
    }
    printf("PIO WRIT ADDR: %x %c\n", addr, value);
    /* for(int i=0; i<BX_GENERAL_REGISTERS+4; i++){ */
    /*     printf("%d: %lx\n",i, BX_CPU(id)->gen_reg[i].rrx); */
    /* } */
    return;
    assert(false); 
}

Bit32u bx_pci_device_c::pci_read_handler(unsigned char, unsigned int) { assert(false); return 0; }

logfunctions *pluginlog;
bx_devices_c bx_devices;
