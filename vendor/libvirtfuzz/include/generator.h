#ifndef GENERATOR_H
#define GENERATOR_H

#include <random>

#include "messages.pb.h"
#include "common.h"

uint64_t evaluateIntraDepNode(const device::IntraDepNode &node, std::mt19937 &rng, std::unordered_map<uint64_t, uint64_t>& common_values);

virtfuzz::Message generateMessage(std::mt19937 &rng);
virtfuzz::Message generateMessageFromOp(const device::Operation &operation, std::mt19937 &rng);
virtfuzz::Message generateMessageRandom(std::mt19937 &rng, bool is_dma);

virtfuzz::MessageSequence generateMessages(std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesRandom(std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesFromOps(std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesFromDeviceBBs(std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesFromDeviceFuncs(std::mt19937& rng);

virtfuzz::MessageSequence generateMessagesFromCallee(const device::Callee& callee, std::mt19937& rng);
virtfuzz::MessageSequence generateMessagesFromOpKey(const device::CalleeOrOp &calleeOrOp, std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesFromBBKey(const std::string& bb_key, std::mt19937 &rng);
virtfuzz::MessageSequence generateMessagesFromFunctionPaths(const std::string& func_name, std::mt19937& rng);

void processStructure(const device::Structure& structure, uint32_t& size, std::vector<uint8_t>* data, std::mt19937 &rng, uint32_t &start_pos, uint32_t &end_pos, bool &is_gen);

#endif // GENERATOR_H
