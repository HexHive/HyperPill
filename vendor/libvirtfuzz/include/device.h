#ifndef DEVICE_H
#define DEVICE_H

#include <vector>
#include <string>
#include <variant>
#include <random>
#include "virtfuzz.h" // Assuming virtfuzz.h contains the definition for Message and other related types
#include "generator.h"
#include "device.pb.h"

using namespace device;

extern std::unordered_map<uint32_t, std::vector<IntraDepNode>> addr_value_map;

int init_model(const char* file_path);

#endif // DEVICE_H
