#ifndef COMMON_H
#define COMMON_H

#include "device.pb.h"
#include "messages.pb.h"
#include "virtfuzz.h"

#include <random>

const int POSSIBIILTY = 90;

extern device::Device device_model;
extern device::DMAInfo dma_info;
extern device::VirtIODMAInfo virtio_dma_info;
extern std::unordered_map<int, std::vector<int>> bb_operation_ids;

extern std::vector<InterfaceDescription> Interfaces;
extern std::vector<uint8_t> mmio_region_ids;
extern std::vector<uint8_t> pio_region_ids;
extern std::vector<uint8_t> dma_region_ids;

template <typename T>
T randomData(T min, T max, std::mt19937 &rng) {
    std::uniform_int_distribution<T> dist(min, max);
    return dist(rng);
}

template <typename T>
T randomChoice(const std::vector<T>& values, std::mt19937 &rng) {
    std::uniform_int_distribution<size_t> dist(0, values.size() - 1);
    return values[dist(rng)];
}

bool isDeviceInitialized();
bool isDMAInitialized();
bool isVirtIODMAInitialized();

virtfuzz::DataSize getRandomDataSize(std::mt19937& rng, bool is_pio);

std::string messageSequenceToReadableString(const virtfuzz::MessageSequence& message_sequence);
std::string messageToReadableString(const virtfuzz::Message& message);

uint8_t get_state();
void set_state(uint8_t);

#endif
