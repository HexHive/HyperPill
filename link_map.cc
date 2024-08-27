#include <stdlib.h>
#include <fstream>
#include <regex>
#include "fuzz.h"

void load_link_map(char* map_path, char* obj_regex, size_t base) {
    std::regex rx(obj_regex);

    // Need to make sure __llvm_prf_cnts is in the linkmap. Then read the first
    // one that is nonzero - which should have the size of the counters map and
    // the entire region

    std::ifstream infile(map_path);
    std::string line;
    while (std::getline(infile, line))
    {
        std::smatch match;
        if(std::regex_search(line, match, rx)){
            /* printf("MATCH: %s\n", line.c_str()); */
            std::istringstream iss(line);
            uint64_t start, len;
            std::string ignore;
            char c;
            if (!(iss >> std::hex  >> ignore >> start >> len)) { break; } 
            add_pc_range(base+start, len);
        }
    }
}
