#include "device.h"
#include "debug.h"
#include <map>
#include <sstream>
#include <iostream>
#include <regex>
#include <variant>
#include <fstream>
#include <google/protobuf/util/json_util.h>

std::unordered_map<uint32_t, std::vector<IntraDepNode>> addr_value_map;

int init_model(const char* file_path) {
	std::string json_file_path = std::string(file_path);
    std::ifstream input(json_file_path, std::ios::binary);
    if (!input) {
        std::cerr << "Failed to open file: " << json_file_path << std::endl;
        return 1;
    }

    std::string json_data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    google::protobuf::util::JsonParseOptions options;
    auto status = google::protobuf::util::JsonStringToMessage(json_data, &device_model, options);

    // std::cout << "Parsed Device Moel: " << std::endl;
    // std::cout << device_model.DebugString() << std::endl;

	std::cout << "Parsed device model successfully!" << std::endl;

	return 0;
}
