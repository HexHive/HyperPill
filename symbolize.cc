#include "fuzz.h"
#include <stdlib.h>
#include <string>
#include <fstream>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <array>
#include <map>
#include <experimental/filesystem>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>

namespace fs = std::experimental::filesystem;

static std::map<std::string, std::pair<uint8_t*, size_t>> elfs;
static std::map<std::pair<size_t, size_t>, std::string> ranges;

static bool enabled;
void load_symbolization_files(char* path) {
    enabled = 1;
    for (const auto & entry : fs::directory_iterator(path)) {
        verbose_printf(":: Loading symbols from %s\n", entry.path().c_str());
        fflush(stdout);
        std::ifstream infile(entry.path(), std::ios_base::in | std::ios_base::binary);
        int fd = open(entry.path().c_str(), O_RDONLY);
        struct stat  sb;
        fstat(fd, &sb);
        size_t map_size = (sb.st_size|0xFFF)+1;
    
        uint8_t *ptr = (uint8_t*)mmap(NULL, map_size , PROT_READ, MAP_PRIVATE, fd, 0);
        elfs[entry.path()] = std::make_pair(ptr, sb.st_size);
        close(fd);
    }
}

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif
static size_t offset_to_address(const char* path, Elf64_Off offset, size_t *voffset, size_t *shaddr, size_t *size, char* name) {
    struct stat statbuf;
    FILE *file = fopen(path, "rb");
    fstat(fileno(file), &statbuf);

    Elf64_Ehdr *ehdr = (ElfW(Ehdr) *)mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE, fileno(file), 0);
    uint8_t* boff = (uint8_t*)ehdr;
    fclose(file);
    if(ehdr == MAP_FAILED) {
        printf("map failed\n");
        return 0;
    } else {
        printf("mmapped the file: %d program headers\n", ehdr->e_shnum);
    }
    Elf64_Shdr *shdr = (ElfW(Shdr) *)(ehdr->e_shoff + (size_t)ehdr);
    char* section_name_table = (char *) (boff + shdr[ehdr->e_shstrndx].sh_offset);
    int i;
    size_t result = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        printf("Comparing: type: %d %lx vs %lx-%lx %s\n",shdr[i].sh_type, offset, shdr[i].sh_offset,shdr[i].sh_offset + shdr[i].sh_size, section_name_table + shdr[i].sh_name);
        if (shdr[i].sh_type == SHT_PROGBITS) {
            if (offset >= shdr[i].sh_offset && offset < shdr[i].sh_offset + shdr[i].sh_size) {
                *voffset = offset - shdr[i].sh_offset;
                *size = shdr[i].sh_size;
                *shaddr = shdr[i].sh_addr;
                strncpy(name, section_name_table + shdr[i].sh_name, 99);
                break;
            }
        }
    }

    munmap(ehdr, statbuf.st_size);
    return 0;
}

void symbolize(size_t pc) {
    if(!enabled)
        return;
    uint8_t  instr_buf[4096];

    for (auto &range: ranges) {                                                               
        if(pc >= range.first.first && pc < range.first.first + range.first.second)
            return ;
    }                                                                                         
    printf("Trying to read from %lx\n", pc&(~0xFFFLL));
    bool valid = cpu0_read_instr_buf(pc, instr_buf);
    if (!valid)
        abort();

    std::string match;
    size_t file_offset = 0;
    size_t match_addr;
    size_t tries = 0;
    while(!file_offset && tries++ < 10) {
        size_t segment_length = 40;
        size_t offset = rand()%(4096-segment_length);
        for(auto &elf :elfs) {
            printf("searching %s for code chunk\n", elf.first.c_str());
            size_t sum = 0;
            for(int i=offset; i<offset+segment_length; i++) {
                sum += instr_buf[i];
                printf("%02x ", instr_buf[i]);
                if(i%16 ==0)
                    printf("\n");
            }
            printf("\n");
            fflush(stdout);
            if(!sum) {
                tries--;
                break;
            }
            auto res = (uint8_t*)memmem(elf.second.first, elf.second.second, instr_buf+offset, segment_length);
            if(res) {
                auto dist = res - elf.second.first;
                printf("Found match %lx\n", dist);
                if(file_offset || memmem((uint8_t*)res+1, elf.second.second-(res-elf.second.first), instr_buf+offset, segment_length) != NULL){
                    printf("... Duplicate\n");
                    file_offset = 0;
                    break;
                }
                fflush(stdout);
                match = elf.first;
                file_offset = dist;
                match_addr = (pc&(~0xFFFLL)) + offset;
            }
        }
    }
    if(!file_offset)
        return;
    size_t voffset = 0, size = 0, shaddr = 0;
    char name[100];
    offset_to_address(match.c_str(), file_offset, &voffset, &shaddr, &size, name);
    printf("MATCH ADDR %lx VOFFSET %lx SIZE %lx\n", match_addr, voffset, size);
    size_t vstart = match_addr - voffset;
    ranges[std::make_pair(vstart, size)] = match;
    printf("Symbolization Range: %lx - %lx size: %lx file: %s section: %s sh_addr: %lx \n", vstart, vstart+size, size, match.c_str(), name, shaddr);
    if(size < 0x500) {
        uint8_t* malc = (uint8_t*)malloc(size);
        cpu0_read_virtual(vstart, size, malc);
        cpu0_read_virtual(match_addr, size, malc);
        for(int i=0; i<size; i++){
            printf("%02x ", malc[i]);
            if(i%0x10==0xf)
                printf("\n");
        }
        printf("\n");
    }
}
