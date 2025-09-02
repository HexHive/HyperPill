#include "fuzz.h"
#include "time.h"
#include <tsl/robin_map.h>
#include <tsl/robin_set.h> 
#include <fstream>
#include <iostream>
#include <string>

tsl::robin_map<hp_address, bool> ignore_edges;
tsl::robin_set<hp_address> seen_edges;
tsl::robin_map<hp_address, uint64_t> all_edges;
tsl::robin_map<hp_address, uint64_t> edge_to_idx;

tsl::robin_set<hp_address> cur_input;

std::vector<std::pair<size_t, size_t>> pc_ranges;
std::vector<std::pair<size_t, size_t>> our_stacktrace;

__attribute__((section(
    "__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[32 << 10];

uint32_t status = 0;

extern std::map<std::string, std::pair<uint64_t, uint64_t>> regions;

void save_seen_edges(const std::string& filename) {
    std::ofstream ofs(filename, std::ios::out | std::ios::trunc);

    // https://www.ayrx.me/drcov-file-format/
    ofs << "DRCOV VERSION: 2" << "\n";
    ofs << "DRCOV FLAVOR: drcov" << "\n";

    int idx = 0;
    std::map<std::string, int> bins;
    ofs << "Module Table: version 2, count " << regions.size() << "\n";
    ofs << "Columns: id, base, end, entry, path" << "\n";
    for (const auto& [name, range] : regions) {
        ofs << idx << ", " \
            << "0x" << std::hex << range.first << ", " \
            << "0x" << std::hex << range.first + range.second << ", " \
            << "0x0000000000000000, " << name << "\n";
        bins[name] = idx;
        idx++;
    }

    ofs << "BB Table: " << std::dec << seen_edges.size() << " bbs" << "\n";
    for (const auto& pc : seen_edges) {
        addr_bin_name addr_bin_name;
        addr_bin_name.addr = pc;
        addr_to_sym(&addr_bin_name);
        if (addr_bin_name.bin) {
            auto range = regions.find(addr_bin_name.bin);
            uint32_t start = pc - range->second.first;
        #if defined(HP_X86_64)
            uint16_t size = 1;
        #else defined(HP_AARCH64)
            uint16_t size = 4;
        #endif
            auto idx  = bins.find(addr_bin_name.bin);
            uint16_t mod_id = idx->second;
            ofs.write(reinterpret_cast<const char*>(&start), sizeof(start));
            ofs.write(reinterpret_cast<const char*>(&size), sizeof(size));
            ofs.write(reinterpret_cast<const char*>(&mod_id), sizeof(mod_id));
        }
    }
    ofs.close();
}

void add_pc_range(size_t base, size_t len) {
    printf("Will treat: %lx +%lx as coverage\n", base, len);
    pc_ranges.push_back(std::make_pair(base, len));
}

bool ignore_pc(hp_address pc) {
    if (pc_ranges.size() == 0) // No ranges = fuzz everthing
        return false;
    if (ignore_edges.find(pc) == ignore_edges.end()) {
        bool ignore = true;
        for (auto &r : pc_ranges) {
            if (pc >= r.first && pc <= r.first + r.second) {
                ignore = false;
                break;
            }
        }
        ignore_edges[pc] = ignore;
    }
    return ignore_edges[pc];
}

static size_t last_new = 0;

void print_stacktrace(){
    printf("Stacktrace:\n");
    if(empty_stacktrace())
        return;
    for (auto r = our_stacktrace.rbegin(); r != our_stacktrace.rend(); ++r)
    {
        printf("%016lx -> %016lx\n", r->first, r->second);
    }
    fflush(stdout);
    fflush(stderr);
}

void add_edge(hp_address prev_rip, hp_address new_rip) {
    time_t t;

    symbolize(new_rip);
    if(fuzzing) {
        if(cur_input.emplace(new_rip).second)
            last_new = 0;
        if(last_new++ > 1000000 && !master_fuzzer ){
            printf("No new edges for over %d..\n", last_new);
            fuzz_emu_stop_unhealthy();
        }
        if(last_new > 3000000 && master_fuzzer ){
            printf("No new edges for over %d..\n", last_new);
            fuzz_stacktrace();
            fuzz_emu_stop_unhealthy();
        }
    }

    if (ignore_pc(new_rip))
        return;
    libfuzzer_coverage[new_rip % sizeof(libfuzzer_coverage)]++;


    if (seen_edges.emplace(new_rip).second) {
        time(&t);
        addr_bin_name addr_bin_name;
        addr_bin_name.addr = new_rip;
        addr_to_sym(&addr_bin_name);
        printf("[%d] NEW_PC: %lx %s (%s +%d)\n", t, new_rip, addr_bin_name.bin, addr_bin_name.name, addr_bin_name.off);
        status |= (1 << 1); // new pc
    }
}

void reset_op_cov() {
    last_new = 0;
}
void reset_cur_cov() {
    our_stacktrace.clear();
    cur_input.clear();
    last_new = 0;
    libfuzzer_coverage[0] = 1;
}

uint32_t get_sysret_status(void) { return status; }

void reset_sysret_status(void) { status = 0; }

void set_sysret_status(uint32_t new_status) { status = new_status; }

void add_stacktrace(hp_address branch_rip, hp_address new_rip) {
    our_stacktrace.push_back(std::make_pair(branch_rip, new_rip));
}

void pop_stacktrace(void) {
    our_stacktrace.pop_back();
}

bool empty_stacktrace(void) {
    return our_stacktrace.empty();
}

void fuzz_stacktrace(){
    /* if(master_fuzzer) */
    if(fuzzing)
        ic_dump();
    static void *log_crashes = getenv("LOG_CRASHES");
    if(!log_crashes)
        return;
    print_stacktrace();
}
