#include "fuzz.h"

#include <stdio.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include  <signal.h>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>

static int coverage_dump_precision = 300;
static uint64_t last_coverage_dump;

// The format of the header:
/* See: https://github.com/llvm/llvm-project/blob/36daf3532d91bb3e61d631edceea77ebb8417801/compiler-rt/include/profile/InstrProfData.inc#L126
INSTR_PROF_RAW_HEADER(uint64_t, Magic, __llvm_profile_get_magic())
INSTR_PROF_RAW_HEADER(uint64_t, Version, __llvm_profile_get_version())
INSTR_PROF_RAW_HEADER(uint64_t, BinaryIdsSize, __llvm_write_binary_ids(NULL))
INSTR_PROF_RAW_HEADER(uint64_t, DataSize, DataSize)
INSTR_PROF_RAW_HEADER(uint64_t, PaddingBytesBeforeCounters, PaddingBytesBeforeCounters)
INSTR_PROF_RAW_HEADER(uint64_t, CountersSize, CountersSize)
INSTR_PROF_RAW_HEADER(uint64_t, PaddingBytesAfterCounters, PaddingBytesAfterCounters)
INSTR_PROF_RAW_HEADER(uint64_t, NamesSize,  NamesSize)
INSTR_PROF_RAW_HEADER(uint64_t, CountersDelta,
                      (uintptr_t)CountersBegin - (uintptr_t)DataBegin)
INSTR_PROF_RAW_HEADER(uint64_t, NamesDelta, (uintptr_t)NamesBegin)
INSTR_PROF_RAW_HEADER(uint64_t, ValueKindLast, IPVK_Last)

Eg:
00000000: 8172 666f 7270 6cff 0800 0000 0000 0000  .rforpl.........
00000010: 2000 0000 0000 0000 0fb0 0000 0000 0000   ...............
00000020: 0000 0000 0000 0000 bb55 0300 0000 0000  .........U......
00000030: 0000 0000 0000 0000 ce76 6d00 0000 0000  .........vm.....
00000040: 2852 e5ff ffff ffff 8dd1 3959 5555 0000  (R........9YUU..
00000050: 0100 0000 0000 0000 1400 0000 0000 0000  ................

*/

static uint64_t base;

static uint64_t get_addr_of_symbol(const char* symbolname)
{
    FILE *fp;
    char addr[100];

    char cmd[500];
    snprintf(cmd, 500, NM_PREFIX"nm --defined-only -n %s | grep %s | cut -f1 -d ' '", getenv("LINK_OBJ_PATH"), symbolname);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command %s\n", cmd);
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    while (fgets(addr, sizeof(addr), fp) != NULL) {
        printf("%s: %s", symbolname, addr);
        return strtoll(addr, NULL, 16);
    }
    return NULL;
}

static uint64_t pdstart, pdstop, pdsize;
static uint64_t pcstart, pcstop, pcsize;
static uint64_t pnstart, pnstop, pnsize;

static uint8_t *pd, *pc, *pn;

void write_source_cov() {
    // Write Header
    static uint64_t header[11] = {};
	size_t len;
	size_t offset = 0;
    if(!header[0]) {
        uint64_t value;

        // Magic
        memcpy(&header[0], "\x81\x72\x66\x6f\x72\x70\x6c\xff", sizeof(uint64_t));

        // Version
        value = 0x8;
        memcpy(&header[1], &value, sizeof(uint64_t));

        // BinaryIdsSize (just copied from default.profraw)
        value = 0x20;
        value = 0;
        memcpy(&header[2], &value, sizeof(uint64_t));

        // DataSize
        // __start___llvm_prf_data
        // __stop___llvm_prf_data
        // Divide by 8
        value = pdsize/(8*6); 
        memcpy(&header[3], &value, sizeof(uint64_t));

        // PaddingBytesBeforeCounters
        value = 0; 
        memcpy(&header[4], &value, sizeof(uint64_t));

        // CountersSize
        // __start___llvm_prf_cnts
        // __stop___llvm_prf_cnts
        // Divide by 8
        value = pcsize/8; 
        memcpy(&header[5], &value, sizeof(uint64_t));

        // PaddingBytesAfterCounters
        value = 0; 
        memcpy(&header[6], &value, sizeof(uint64_t));                                                   

        // NamesSize
        // __start___llvm_prf_names
        // __stop___llvm_prf_names
        value = pnsize; 
        memcpy(&header[7], &value, sizeof(uint64_t));

        // CountersDelta
        // Address of __start___llvm_prf_cnts
        // Address of __start___llvm_prf_data
        value = pcstart-pdstart; 
        memcpy(&header[8], &value, sizeof(uint64_t));

        // CountersDelta
        // Address of __start___llvm_prf_names
        value = pnstart; 
        memcpy(&header[9], &value, sizeof(uint64_t));

        // ValueKindLast
        value = 1; 
        memcpy(&header[10], &value, sizeof(uint64_t));


		len = pdsize;
		offset = 0;
		while (len) {
			/* printf("Reading pd %lx\n", pd+offset); */
			if(len> 0x1000) {
				cpu0_read_virtual(pdstart+offset, 0x1000, pd + offset);
				len -= 0x1000;
				offset += 0x1000;
			} else {
				cpu0_read_virtual(pdstart+offset, len, pd + offset);
				len = 0;
			}
		}
		len = pnsize;
		offset = 0;
		while (len) {
			/* printf("Reading pn %lx\n", pn+offset); */
			if(len> 0x1000) {
				cpu0_read_virtual(pnstart+offset, 0x1000, pn + offset);
				len -= 0x1000;
				offset += 0x1000;
			} else {
				cpu0_read_virtual(pnstart+offset, len, pn + offset);
				len = 0;
			}
		}
    }

	len = pcsize;
	offset = 0;

    while (len) {
        /* printf("Reading pc %lx\n", pc+offset); */
        if(len> 0x1000) {
            cpu0_read_virtual(pcstart+offset, 0x1000, pc + offset);
            len -= 0x1000;
            offset += 0x1000;
        } else {
            cpu0_read_virtual(pcstart+offset, len, pc + offset);
            len = 0;
        }
    }

    uint8_t padding[10] = {};
    struct iovec iov[] = {
        {header, sizeof(header)},
        {pd, pdsize},
        {pc, pcsize},
        {pn, pnsize},
        {padding, 8-((sizeof(header)+pdsize+pcsize+pnsize)%8)}
    };
    char filename[100];
    sprintf(filename, "%d-%ld.profraw", getpid(), time(NULL));
    int fd = open(filename, O_CREAT|O_RDWR, 0666);
    writev(fd, iov, sizeof(iov)/sizeof(struct iovec));
    close(fd);
}

void  TERMhandler(int sig){
    write_source_cov();
    _exit(0);
}

void check_write_coverage(){
    if(!master_fuzzer || !last_coverage_dump)
        return;
    uint64_t t = time(NULL);
    if(t - last_coverage_dump < coverage_dump_precision)
        return;
    last_coverage_dump=t;
    // following dump
    write_source_cov();
}

static void sig_handler(int signum) {
    uint64_t t = time(NULL);
    switch (signum) {
    case SIGALRM:
        if(t - last_coverage_dump < coverage_dump_precision)
            return;

        last_coverage_dump=t;
        // following dump
        write_source_cov();
        alarm(coverage_dump_precision);
        break;
    }
}

void init_sourcecov(size_t baseaddr) {
    base = baseaddr;

    pdstart = get_addr_of_symbol("__start___llvm_prf_data") + base;
    pdstop = get_addr_of_symbol("__stop___llvm_prf_data") + base;
    pcstart = get_addr_of_symbol("__start___llvm_prf_cnts") + base;
    pcstop = get_addr_of_symbol("__stop___llvm_prf_cnts") + base;
    pnstart = get_addr_of_symbol("__start___llvm_prf_names") + base;
    pnstop = get_addr_of_symbol("__stop___llvm_prf_names") + base;

    pdsize = pdstop-pdstart;
    pcsize = pcstop-pcstart;
    pnsize = pnstop-pnstart;

    pd = (uint8_t*)malloc(pdsize);
    pc = (uint8_t*)malloc(pcsize);
    pn = (uint8_t*)malloc(pnsize);

    memset(pc, 0, pcsize);
    for(size_t page = (pcstart >> 12) << 12;  page < pcstop;  page += 0x1000){
        size_t start, len;
        if(pcstart - page < 0x1000)
            start = pcstart;
        else 
            start = page;

        len = 0x1000 - (start & 0xFFF);

        if(pcstop - page < 0x1000)
            len = pcstop - page;

        hp_phy_address phystart;
        gva2hpa(start, &phystart);

        cpu0_write_virtual(start, len, pc);
        phystart = (phystart & ~((uint64_t) 0xfff)) | (start & 0xfff);
        add_persistent_memory_range(phystart, len);
    }

    /* std::atexit(write_source_cov); */
    /* signal(SIGTERM, TERMhandler); */

}
extern uint64_t icount_limit_floor;
extern uint64_t icount_limit;
void setup_periodic_coverage(){
    char linkpath[100];
    readlink("/proc/self/fd/1", linkpath, 100);
    linkpath[99] = 0;
    if(strstr(linkpath, "fuzz-0.log")){
        if(!getenv("NOCOV")) {
            last_coverage_dump=time(NULL);
            write_source_cov();
        }
        master_fuzzer = true;
    } else if(strstr(linkpath, "fuzz-") && getenv("PROGRESSIVE_TIMEOUT")){
        std::stringstream ss;
        std::regex log_regex("fuzz-(.*).log");
        std::smatch match;
        std::string s = linkpath;
        std::regex_search(s, match, log_regex);
        assert(match.size() > 1);
        ss << std::dec << match[1].str();
        int val;
        ss >> val;
        unsigned long max = strtol(getenv("NSLOTS"), NULL, 10);
        assert(val < max);
        if(max != LONG_MIN){
            icount_limit = icount_limit_floor + ((icount_limit-icount_limit_floor)/(max))*(val-1);
            printf("SET ICOUNT LIMIT: %d\n", icount_limit);
        }
    }
}
