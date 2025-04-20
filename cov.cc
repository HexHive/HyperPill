#include "fuzz.h"
#include "time.h"
#include <tsl/robin_map.h>
#include <tsl/robin_set.h> 

tsl::robin_map<bx_address, bool> ignore_edges;
tsl::robin_set<bx_address> seen_edges;
tsl::robin_map<bx_address, uint64_t> all_edges;
tsl::robin_map<bx_address, uint64_t> edge_to_idx;

tsl::robin_set<bx_address> cur_input;

std::vector<std::pair<size_t, size_t>> pc_ranges;
std::vector<std::pair<size_t, size_t>> our_stacktrace;

__attribute__((section(
    "__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[32 << 10];

uint32_t status = 0;

void add_pc_range(size_t base, size_t len) {
    printf("Will treat: %lx +%lx as coverage\n", base, len);
    pc_ranges.push_back(std::make_pair(base, len));
}

bool ignore_pc(bx_address pc) {
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
    if(our_stacktrace.empty())
        return;
    for (auto r = our_stacktrace.rbegin(); r != our_stacktrace.rend(); ++r)
    {
        printf("%016lx -> %016lx\n", r->first, r->second);
    }
    fflush(stdout);
    fflush(stderr);
}

void add_edge(bx_address prev_rip, bx_address new_rip) {
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
        auto s = addr_to_sym(new_rip);
        printf("[%d] NEW_PC: %lx %s (%s)\n", t, new_rip, s.second.c_str(), s.first.c_str());
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

void fuzz_instr_cnear_branch_taken(bx_address branch_rip, bx_address new_rip) {
    add_edge(branch_rip, new_rip);
}

void fuzz_instr_cnear_branch_not_taken(bx_address branch_rip) {}

uint32_t get_sysret_status() { return status; }

void reset_sysret_status() { status = 0; }


void fuzz_stacktrace(){
    /* if(master_fuzzer) */
    if(fuzzing)
        ic_dump();
    static void *log_crashes = getenv("LOG_CRASHES");
    if(!log_crashes)
        return;
    print_stacktrace();

}
void fuzz_instr_ucnear_branch(unsigned what, bx_address branch_rip,
                              bx_address new_rip) {
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret
    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT) && BX_CPU(0)->user_pl ) {
        our_stacktrace.push_back(std::make_pair(branch_rip, new_rip));
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && BX_CPU(0)->user_pl&& !our_stacktrace.empty()) {
        our_stacktrace.pop_back();
        /* fuzz_stacktrace(); */
    }
    add_edge(branch_rip, new_rip);
}

void fuzz_instr_far_branch(unsigned what, Bit16u prev_cs, bx_address prev_rip,
                           Bit16u new_cs, bx_address new_rip) {
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret

    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT) && BX_CPU(0)->user_pl) {
        our_stacktrace.push_back(std::make_pair(prev_rip, new_rip));
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && BX_CPU(0)->user_pl && !our_stacktrace.empty()) {
        our_stacktrace.pop_back();
        /* fuzz_stacktrace(); */
    }

    if (what == BX_INSTR_IS_IRET && (new_rip >> 63) == 0)
        add_edge(prev_rip, new_rip);
}
