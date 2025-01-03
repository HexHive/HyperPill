#include <vector>
#include <map>
#include <stdint.h>
#include "fuzz.h"
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <numeric>

#include <tsl/robin_set.h>
#include <tsl/robin_map.h>

#if defined(HP_X86_64)
static std::vector<std::tuple<hp_address, hp_address, unsigned int>> ept_exit_ranges; // Start, Base, Reason

static std::vector<bool> identify_ports_by_icount_frequency(std::vector<uint32_t> icounts) {
    // calculate icounts with lowest frequency
    std::unordered_map<uint32_t, uint32_t> frequencies;
    std::unordered_set<uint32_t> frequent_icounts;
    std::vector<bool> pio_regions(0xFFFF+1, 0);
    for (auto& icount : icounts) {
        if (frequencies.find(icount) == frequencies.end()) {
            frequencies[icount] = 1;
        } else {
            frequencies[icount]++;
        }
    }
    std::vector<std::pair<uint32_t,uint32_t>> sorted(frequencies.begin(), frequencies.end());
    std::sort(sorted.begin(), sorted.end(), 
            [](std::pair<uint32_t,uint32_t>& a, std::pair<uint32_t,uint32_t>& b) { 
                return a.second < b.second;
            }); 
    printf("[identify_ports_from_icount] Lowest icount frequencies\n");
    for (auto& it : sorted) {
        printf("  [ %u ]: %u | log %.2lf\n", it.first, it.second, log(it.second));
    }
    float upper_bound = 5.4;
    printf("[identify_ports_from_icount] Infer PIO ports"
           " using upper_bound icount frequency (log) = [ %lf ]\n", upper_bound);
    for (auto& it : sorted) {
        if (log(it.second) < upper_bound) {
            frequent_icounts.insert(it.first);
        } else {
            break;
        }
    }
    for (uint32_t i = 0x0; i <= 0xFFFF; ++i) {
        if (frequent_icounts.find(icounts[i]) != frequent_icounts.end()) {
            printf("Found open port at [ 0x%x ]\n", i);
            pio_regions[i] = 1;
        }
    }
    return pio_regions;
}

static std::vector<bool> identify_ports_by_icount_distribution(
        std::vector<uint32_t> icounts) {
    std::vector<bool> pio_regions(0xFFFF+1, 0);

    double mean = std::accumulate(
            icounts.begin(), icounts.end(), 0.0) / icounts.size();
    double sq_sum = std::inner_product(icounts.begin(), icounts.end(), icounts.begin(), 0.0,
        [](double const & x, double const & y) { return x + y; },
        [mean](double const & x, double const & y) { return (x - mean) * (y - mean); });
    double stddev = std::sqrt(sq_sum / icounts.size());

    printf("  mean: %lf stddev: %lf\n", mean, stddev);

    float factor = 0.1;

    for (int i = 0x0; i <= 0xFFFF; i++) {
        if (icounts[i] >= (mean + factor * stddev)) {
            printf("Found open port at [ 0x%x ]\n", i);
            pio_regions[i] = 1;
        }
    }

    return pio_regions;
}

static std::vector<uint32_t> get_pio_icounts() {
    // idealy, we sum the icounts of injected pio read and write
    // however, out to port 0x20 in KVM results in an infinite loop
    std::vector<uint32_t> pio_icounts(0xFFFF + 1, 0);
    uint64_t icount_read, icount_write = 0;

    for (uint32_t i = 0x0; i <= 0xFFFF; i += 0x1) {
        clear_indicator_values();
        add_indicator_value(i);

        inject_in(i, 0);
        start_cpu();
        icount_read = get_pio_icount();
        reset_vm();

        pio_icounts[i] = icount_read + icount_write;
        printf("Port %x %lx\n", i, pio_icounts[i]);
    }

    for (uint32_t i = 0x0; i <= 0xFFFF; i += 0x1) {
        printf("  port %x: icount = %x\n", i, pio_icounts[i]);
    }

    return pio_icounts;
}

static std::map<uint16_t, uint16_t> merge_pio_regions(std::vector<bool> pio_regions) {
    std::map<uint16_t, uint16_t> regions;

    for (uint32_t i = 0x0; i <= 0xFFFF; i += 0x1){
        if (!pio_regions[i]) continue;
        uint16_t entry;
        uint16_t previous;
        if (i - previous != 1){
            entry = i;
        }
        regions[entry]+=1;
        previous = i;
    }

    return regions;
}

void enum_pio_regions() {
    std::vector<uint32_t> pio_icounts;
    std::vector<bool> pio_region_markups;
    std::map<uint16_t, uint16_t> merged_regions; // std::map<offset, size>

    pio_icounts = get_pio_icounts();

    pio_region_markups = identify_ports_by_icount_distribution(pio_icounts);
    merged_regions = merge_pio_regions(pio_region_markups);

    printf("\n--- PIO Ranges ---\n");
    for (auto &a : merged_regions) {
        printf("PIO Range: 0x%lx 0x%lx\n", a.first, a.second);
        insert_pio(a.first, a.second);
    }
}

void enum_handle_ept_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end) {
    ept_exit_ranges.push_back(std::make_tuple(gap_start, gap_end, gap_reason));
    if(gap_reason == VMX_VMEXIT_EPT_MISCONFIGURATION) 
        printf("%lx +%lx Potential Misconfig\n", gap_start, gap_end - gap_start);
    else if(gap_reason == VMX_VMEXIT_EPT_VIOLATION)
        printf("%lx +%lx Potential Violation\n", gap_start, gap_end - gap_start);
    else
        abort();
}

void enum_mmio_regions(void) {
    tsl::robin_set<uint64_t> seen_icounts;
    std::vector<std::pair<hp_address,hp_address>> mmio_ranges;
    hp_address mmio_start = 0;
    for (auto &a : ept_exit_ranges){
        hp_address addr = std::get<0>(a);
        hp_address base = addr;
        hp_address end = std::get<1>(a);
        unsigned int reason = std::get<2>(a);
        // printf("EPT Exit Range: 0x%lx - 0x%lx (%s)\n", addr, end, reason == VMX_VMEXIT_EPT_MISCONFIGURATION ? "misconfig":"violation");
        while(addr < end && addr - base < 0x10000000) { 
            bool new_icount = 0;
            inject_write(addr, 2,1);
            start_cpu();
            uint32_t status = get_sysret_status();
            uint64_t icount = get_icount();

            printf("MMIO: %lx Icount %lx Sysret: %lx ", addr, icount, status);
            printf("\n");
            if (seen_icounts.emplace(icount).second) {
                new_icount =1 ; // new icount
            }
            if (status & 1) {
                if (!mmio_start) {
                    mmio_start = addr;
                }
            } else if (mmio_start) {
                mmio_ranges.push_back(std::make_pair(mmio_start, addr - mmio_start));
                mmio_start = 0;
            }

            if(new_icount & 1) {
                addr += 0x1000;
            } else {
                addr = (addr&(~0xFFFF)) + 0x10000;
            }

            reset_sysret_status();
            reset_vm();
            reset_cur_cov();
        }
        if (mmio_start) {
            mmio_ranges.push_back(std::make_pair(mmio_start, addr - mmio_start));
            mmio_start = 0;
        }
    }
    printf("\n--- MMIO Ranges ---\n");
    for (auto& it : mmio_ranges) {
        printf("MMIO Range: 0x%lx 0x%lx\n", it.first, it.second);
        insert_mmio(it.first, it.second);
    }
}
#endif
