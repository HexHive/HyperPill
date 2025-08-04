#include "fuzz.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>
#include <cstdlib>
#include <cstdio>
#include <set>


static std::set<std::string> bins;
static std::map<size_t, std::vector<std::pair<std::string, std::string>>> addr2sym;
static std::map<std::pair<std::string, std::string>, uint64_t> sym2addr;


// todo: dynamic libc symbols for stuff like exit etc
// Strategy: Run objdump on the binary. Load the
bool sym_to_addr(addr_bin_name *addr_bin_name) {
    std::string bin(addr_bin_name->bin);
    std::string name(addr_bin_name->name);
    for(auto it: bins) {
        if(it.find(bin) != std::string::npos){
            addr_bin_name->addr = sym2addr[std::make_pair(std::string(it), name)];
            return true;
        }
    }
    addr_bin_name->addr = NULL;
    return false;
}

uint64_t sym_to_addr2(const char *bin, const char *name) {
    addr_bin_name addr_bin_name;
    addr_bin_name.bin = bin;
    addr_bin_name.name = name;
    sym_to_addr(&addr_bin_name);
    return addr_bin_name.addr;
}

bool addr_to_sym(addr_bin_name *addr_bin_name) {
    size_t addr = addr_bin_name->addr;
    if(addr2sym.find(addr) != addr2sym.end()) {
        addr_bin_name->bin = addr2sym[addr][0].first.c_str();
        addr_bin_name->name = addr2sym[addr][0].second.c_str();
        addr_bin_name->off = 0;
        return true;
    }
    for(int i =0; i<0x1000; i++){
        if(addr2sym.find(addr-i) != addr2sym.end()){
            addr_bin_name->bin = addr2sym[addr-i][0].first.c_str();
            addr_bin_name->name = addr2sym[addr-i][0].second.c_str();
            addr_bin_name->off = i;
            return true;
        }
    }
    addr_bin_name->bin = NULL;
    addr_bin_name->name = NULL;
    addr_bin_name->off = 0;
    return false;
}

static std::string executeCommand(const char* cmd) {
    std::string result, line;
    char buf[1000];
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;
    while (fgets(buf, 1000, pipe) != nullptr) {
        result += std::string(buf);
    }
    pclose(pipe);
    return result;
}

// Function to parse the output of 'nm' command and construct map of addresses to symbol names
static std::map<std::string, size_t> get_symbol_map(const std::string& binaryPath) {
    std::map<std::string, size_t> symbolMap;
    std::string nmOutput = executeCommand(("nm -n -C -a " + binaryPath + "| grep -e ' t ' -e ' T ' -e ' B '").c_str());
    size_t pos = 0;
    while ((pos = nmOutput.find("\n")) != std::string::npos) {
        std::string line = nmOutput.substr(0, pos);
        nmOutput.erase(0, pos + 1);
        size_t addrEnd = line.find(' ');
        size_t nameStart = line.find(' ', addrEnd + 1);
        if (addrEnd != std::string::npos && nameStart != std::string::npos) {
            std::string address = line.substr(0, addrEnd);
            std::string name = line.substr(nameStart + 1);
            symbolMap.emplace(name, strtoull(address.c_str(), NULL, 16));
        }
    }
    nmOutput = executeCommand(("nm -n -C -a -D " + binaryPath + "| grep -e ' t ' -e ' T ' -e ' B '").c_str());
    pos = 0;
    while ((pos = nmOutput.find("\n")) != std::string::npos) {
        std::string line = nmOutput.substr(0, pos);
        nmOutput.erase(0, pos + 1);
        size_t addrEnd = line.find(' ');
        size_t nameStart = line.find(' ', addrEnd + 1);
        if (addrEnd != std::string::npos && nameStart != std::string::npos) {
            std::string address = line.substr(0, addrEnd);
            std::string name = line.substr(nameStart + 1);
            symbolMap.emplace(name, strtoull(address.c_str(), NULL, 16));
        }
    }
    return symbolMap;
}

void load_symbol_map(char *path) {
    uint64_t start, size, sh_addr;
    std::string binfile, section; 
    int log = 0;
    std::ifstream file(path);
    std::string str; 
    std::stringstream ss;
    std::regex reg_regex("Symbolization Range: (\\w+) - (\\w+) size: (\\w+) file: ([^\\s]+) section: ([^\\s]+) sh_addr: (\\w+)");

    char linkpath[100];
    readlink("/proc/self/fd/1", linkpath, 100);
    linkpath[99] = 0;
    log = (strstr(linkpath, "fuzz-0.log") != NULL);

    printf(".loading symbolization ranges from %s\n", path);
    while (std::getline(file, str))
    {
        std::smatch match; 
        std::regex_search(str, match, reg_regex);
        if(match.size() < 1){
            printf("Unexpected line: %s\n", str.c_str());
            continue;
        }
        ss.clear();
        ss << std::hex << match[1].str(); 
        ss >> start;

        ss.clear();
        ss << std::hex << match[3].str(); 
        ss >> size;

        ss.clear();
        ss << std::hex << match[6].str();
        ss >> sh_addr;
    
        binfile = match[4].str();
        section = match[5].str();
        verbose_printf(":: loaded range: %s %s 0x%lx +0x%lx\n", binfile.c_str(), section.c_str(), start, size);
        bins.insert(binfile);
        if(section == ".text") {
            auto m = get_symbol_map(binfile);
            auto offset = start - sh_addr;
            for(auto it: m) {
                if(it.second) {
                    std::string name = it.first;
                    name.erase(std::find(name.begin(), name.end(), '('), name.end());
                    /* std::replace(name.begin(), name.end(), '(', '\0'); */
                    addr2sym[it.second + offset].push_back(std::make_pair(binfile, name));
                    if(log)
                        printf(".info Symbol Name added: %s@%s %lx\n", name.c_str(), binfile.c_str(), it.second+offset);
                    sym2addr[std::make_pair(binfile, name)] = it.second + offset;
                    // printf("Looking up %s@%s %lx\n", name.c_str(), binfile.c_str(), sym2addr[std::make_pair(binfile, name)]);
                    /* if(!sym2addr.emplace(std::make_pair(binfile, name), it.second + offset).second) */
                    /*     printf(".warning Symbol Name Collision: %s@%s %lx %lx\n", name.c_str(), binfile.c_str(), it.second+offset, sym2addr[std::make_pair(binfile, name)]); */
                }
            }
        }
    }
    printf("sym2addr: vmlinux, init_task %lx\n", sym_to_addr2("vmlinux", "init_task"));
    printf("sym2addr: vmlinux, dump_stack %lx\n", sym_to_addr2("vmlinux", "dump_stack"));
    printf("sym2addr: vmlinux, do_idle %lx\n", sym_to_addr2("vmlinux", "do_idle"));
}
