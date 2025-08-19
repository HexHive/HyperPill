#include "mutator.h"
#include "generator.h"
#include "device.h"
#include "debug.h"

#include <iostream>
#include <sstream>

void Mutate_InsertMessage(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
	virtfuzz::Message new_message = generateMessage(rng);
    std::uniform_int_distribution<int> dist(0, message_sequence.messages_size());
    int index = dist(rng);

    std::vector<virtfuzz::Message> messages(message_sequence.mutable_messages()->begin(), message_sequence.mutable_messages()->end());
    messages.insert(messages.begin() + index, new_message);

    message_sequence.clear_messages();
    for (const auto& msg : messages) {
        *message_sequence.add_messages() = msg;
    }
}

void Mutate_RemoveMessage(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        std::uniform_int_distribution<int> dist(0, message_sequence.messages_size() - 1);
        int index = dist(rng);
        message_sequence.mutable_messages()->DeleteSubrange(index, 1);
    }
}

void Mutate_ReplaceMessage(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        int index = randomData<int>(0, message_sequence.messages_size() - 1, rng);
        virtfuzz::Message new_message = generateMessage(rng);
        *message_sequence.mutable_messages(index) = new_message;
    }
}

void Mutate_ShuffleMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    std::vector<virtfuzz::Message> messages(message_sequence.mutable_messages()->begin(), message_sequence.mutable_messages()->end());
    std::shuffle(messages.begin(), messages.end(), rng);
    message_sequence.clear_messages();
    for (const auto& msg : messages) {
        *message_sequence.add_messages() = msg;
    }
}

void Mutate_InsertRepeatedMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        std::uniform_int_distribution<int> index_dist(0, message_sequence.messages_size() - 1);
        int index = index_dist(rng);
        
        const virtfuzz::Message& original_message = message_sequence.messages(index);

        std::uniform_int_distribution<int> count_dist(1, 5); // FIXME:HyperParameters
        int repeat_count = count_dist(rng);

        std::vector<virtfuzz::Message> messages(message_sequence.mutable_messages()->begin(), message_sequence.mutable_messages()->end());
        messages.reserve(messages.size() + repeat_count);
        
        for (int i = 0; i < repeat_count; ++i) {
            messages.insert(messages.begin() + index + 1, original_message);
        }

        message_sequence.clear_messages();
        for (const auto& msg : messages) {
            *message_sequence.add_messages() = msg;
        }
    }
}

void Mutate_SwapMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 1) {
        size_t n_messages = message_sequence.messages_size();
        size_t split_idx = (std::uniform_int_distribution<size_t>(0, n_messages - 1)(rng)) / 2 + 1;
        
        std::vector<virtfuzz::Message> first_half(message_sequence.mutable_messages()->begin(), message_sequence.mutable_messages()->begin() + split_idx);
        std::vector<virtfuzz::Message> second_half(message_sequence.mutable_messages()->begin() + split_idx, message_sequence.mutable_messages()->end());

        message_sequence.clear_messages();

        for (const auto& msg : second_half) {
            *message_sequence.add_messages() = msg;
        }
        for (const auto& msg : first_half) {
            *message_sequence.add_messages() = msg;
        }
    }
}

void Mutate_RemoveMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    size_t n_messages = message_sequence.messages_size();
    
    // Ensure there is at least one message to potentially remove
    if (n_messages > 1) {
        size_t n_remove = randomData<size_t>(1, n_messages - 1, rng);

        std::vector<size_t> indices(n_messages);
        std::iota(indices.begin(), indices.end(), 0);

        std::shuffle(indices.begin(), indices.end(), rng);

        indices.resize(n_messages - n_remove);
        std::sort(indices.begin(), indices.end());

        std::vector<virtfuzz::Message> remaining_messages;
        for (size_t idx : indices) {
            remaining_messages.push_back(std::move(*message_sequence.mutable_messages(idx)));
        }

        message_sequence.clear_messages();

        for (const auto& msg : remaining_messages) {
            *message_sequence.add_messages() = msg;
        }
    }
}

void Mutate_InsertMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    size_t n_messages = message_sequence.messages_size();

    size_t insert_idx = randomData<size_t>(0, n_messages, rng);

    virtfuzz::MessageSequence fragment_sequence = generateMessages(rng);

    std::vector<virtfuzz::Message> first_half(message_sequence.mutable_messages()->begin(), message_sequence.mutable_messages()->begin() + insert_idx);
    std::vector<virtfuzz::Message> second_half(message_sequence.mutable_messages()->begin() + insert_idx, message_sequence.mutable_messages()->end());

    message_sequence.clear_messages();

    for (const auto& msg : first_half) {
        *message_sequence.add_messages() = msg;
    }

    for (const auto& msg : fragment_sequence.messages()) {
        *message_sequence.add_messages() = msg;
    }

    for (const auto& msg : second_half) {
        *message_sequence.add_messages() = msg;
    }
}

void Mutate_DuplicateMessages(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    size_t n_messages = message_sequence.messages_size();
    
    if (n_messages > 0) {
        size_t start_idx = randomData<size_t>(0, n_messages - 1, rng);
        size_t end_idx = randomData<size_t>(start_idx, n_messages - 1, rng);

        std::vector<virtfuzz::Message> fragment(
            message_sequence.mutable_messages()->begin() + start_idx,
            message_sequence.mutable_messages()->begin() + end_idx + 1);

        for (const auto& msg : fragment) {
            *message_sequence.add_messages() = msg;
        }
    }
}

void Mutate_ChangeAddr(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        int index = randomData<int>(0, message_sequence.messages_size() - 1, rng);
        auto* message = message_sequence.mutable_messages(index);

        auto randomValueChange = [&rng]() -> int {
            std::uniform_int_distribution<int> dist(0, 3);
            int choices[4] = {1, 2, 4, 8};
            int choice = choices[dist(rng)];
            std::uniform_int_distribution<int> sign_dist(0, 1);
            return sign_dist(rng) == 0 ? choice : -choice;
        };

        auto mutateAddrOrPort = [&](uint32_t addrOrPort, uint32_t max_size) -> uint32_t {
            std::uniform_int_distribution<int> mutate_dist(0, 1);
            uint32_t new_value;
            if (mutate_dist(rng) == 0) {
                int change = randomValueChange();
                new_value = addrOrPort + change;
                if (new_value >= max_size) {
                    new_value = max_size - 1;
                }
            } else {
                new_value = randomData<uint32_t>(0, max_size - 1, rng);
            }
            return new_value;
        };

        if (message->has_mmio_read_message()) {
            uint32_t addr = message->mmio_read_message().addr();
            uint32_t region_id = message->mmio_read_message().region_id();
            if (region_id < Interfaces.size() && Interfaces[region_id].type == INTERFACE_TYPE_MMIO) {
                uint32_t max_size = Interfaces[region_id].size;
                uint32_t base_addr = Interfaces[region_id].addr;
                message->mutable_mmio_read_message()->set_addr(base_addr + mutateAddrOrPort(addr - base_addr, max_size));
            }
        } else if (message->has_mmio_write_message()) {
            uint32_t addr = message->mmio_write_message().addr();
            uint32_t region_id = message->mmio_write_message().region_id();
            if (region_id < Interfaces.size() && Interfaces[region_id].type == INTERFACE_TYPE_MMIO) {
                uint32_t max_size = Interfaces[region_id].size;
                uint32_t base_addr = Interfaces[region_id].addr;
                message->mutable_mmio_write_message()->set_addr(base_addr + mutateAddrOrPort(addr - base_addr, max_size));
            }
        } else if (message->has_pio_read_message()) {
            uint16_t port = message->pio_read_message().port();
            uint32_t region_id = message->pio_read_message().region_id();
            if (region_id < Interfaces.size() && Interfaces[region_id].type == INTERFACE_TYPE_PIO) {
                uint32_t max_size = Interfaces[region_id].size;
                uint32_t base_addr = Interfaces[region_id].addr;
                message->mutable_pio_read_message()->set_port(base_addr + mutateAddrOrPort(port - base_addr, max_size));
            }
        } else if (message->has_pio_write_message()) {
            uint16_t port = message->pio_write_message().port();
            uint32_t region_id = message->pio_write_message().region_id();
            if (region_id < Interfaces.size() && Interfaces[region_id].type == INTERFACE_TYPE_PIO) {
                uint32_t max_size = Interfaces[region_id].size;
                uint32_t base_addr = Interfaces[region_id].addr;
                message->mutable_pio_write_message()->set_port(base_addr + mutateAddrOrPort(port - base_addr, max_size));
            }
        } else if (message->has_dma_message()) {
			auto* dma_message = message->mutable_dma_message();
			if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
				if (dma_message->has_dma_random_message()) {
					auto* random_message = dma_message->mutable_dma_random_message();
					random_message->set_index(randomData<uint8_t>(0, 0xFF, rng));
				}
			}
        }
    }
}

std::string getRandomBytes(std::mt19937& rng, size_t length) {
    std::uniform_int_distribution<uint8_t> dist(0, 0xff);
    std::string data(length, '\0');
    for (size_t i = 0; i < length; ++i) {
        data[i] = dist(rng);
    }
    return data;
}

void Mutate_ChangeSize(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        std::uniform_int_distribution<int> dist(0, message_sequence.messages_size() - 1);
        int index = dist(rng);
        auto* message = message_sequence.mutable_messages(index);

        if (message->has_mmio_read_message()) {
            message->mutable_mmio_read_message()->set_size(getRandomDataSize(rng, false));
        } else if (message->has_mmio_write_message()) {
            message->mutable_mmio_write_message()->set_size(getRandomDataSize(rng, false));
        } else if (message->has_pio_read_message()) {
            message->mutable_pio_read_message()->set_size(getRandomDataSize(rng, true));
        } else if (message->has_pio_write_message()) {
            message->mutable_pio_write_message()->set_size(getRandomDataSize(rng, true));
        } else if (message->has_dma_message()) {
			auto* dma_message = message->mutable_dma_message();
            if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
                if (dma_message->has_dma_random_message()) {
                    auto* random_message = dma_message->mutable_dma_random_message();

                    std::uniform_int_distribution<uint32_t> len_dist(1, 1024);  // Adjust range as needed
                    uint32_t new_len = len_dist(rng);
                    random_message->set_len(new_len);
                    random_message->set_data(getRandomBytes(rng, new_len));
                }
            } else if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_VIRTIO) {
            }
        }
    }
}

uint32_t flipBit(uint32_t value, std::mt19937& rng) {
    std::uniform_int_distribution<int> bit_dist(0, 31);
    int bit_to_flip = bit_dist(rng);
    return value ^ (1 << bit_to_flip);
}

uint32_t arithmeticMutate(uint32_t value, std::mt19937& rng) {
    std::uniform_int_distribution<int> op_dist(0, 1);
    std::uniform_int_distribution<int> amount_dist(1, 10);
    int op = op_dist(rng);
    int amount = amount_dist(rng);

    if (op == 0) {
        return value + amount;
    } else {
        return value - amount;
    }
}

uint32_t randomReplacement(std::mt19937& rng) {
    return randomData<uint32_t>(0, std::numeric_limits<uint32_t>::max(), rng);
}

uint32_t byteSwap(uint32_t value) {
    return __builtin_bswap32(value);
}

uint32_t bitwiseNegate(uint32_t value) {
    return ~value;
}

uint32_t increment(uint32_t value) {
    return value + 1;
}

uint32_t decrement(uint32_t value) {
    return value - 1;
}

uint32_t setToZero() {
    return 0;
}

uint32_t setToMax() {
    return std::numeric_limits<uint32_t>::max();
}

uint32_t setToMin() {
    return std::numeric_limits<uint32_t>::min();
}

uint32_t mutateValue(uint32_t value, std::mt19937& rng) {
    std::uniform_int_distribution<int> mutation_dist(0, 9); // Update the range to cover all mutators
    int mutation_type = mutation_dist(rng);

    switch (mutation_type) {
        case 0:
            return flipBit(value, rng);
        case 1:
            return arithmeticMutate(value, rng);
        case 2:
            return randomReplacement(rng);
        case 3:
            return byteSwap(value);
        case 4:
            return bitwiseNegate(value);
        case 5:
            return increment(value);
        case 6:
            return decrement(value);
        case 7:
            return setToZero();
        case 8:
            return setToMax();
        case 9:
            return setToMin();
        default:
            return value;
    }
}

void Mutate_ChangeValue(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        std::uniform_int_distribution<int> dist(0, message_sequence.messages_size() - 1);
        int index = dist(rng);
        auto* message = message_sequence.mutable_messages(index);

        uint32_t original_value = 0;
        uint32_t addr = 0;
        bool has_value = false;

        if (message->has_mmio_write_message()) {
            original_value = message->mmio_write_message().value();
            addr = message->mmio_write_message().addr();
            has_value = true;
        } else if (message->has_pio_write_message()) {
            original_value = message->pio_write_message().value();
            addr = message->pio_write_message().port();
            has_value = true;
        }

        if (has_value) {
            std::uniform_int_distribution<int> change_dist(0, 99);
            int change_type = change_dist(rng);

            uint32_t new_value = original_value;
            if (change_type < 50) {
                auto it = addr_value_map.find(addr);
                if (it != addr_value_map.end() && !it->second.empty()) {
                    const auto& value_nodes = it->second;
                    std::uniform_int_distribution<size_t> value_dist(0, value_nodes.size() - 1);
                    size_t value_index = value_dist(rng);
                    std::unordered_map<uint64_t, uint64_t> common_values;
                    new_value = evaluateIntraDepNode(value_nodes[value_index], rng, common_values);
                } else {
                    new_value = mutateValue(original_value, rng);
                }
            } else {
                new_value = mutateValue(original_value, rng);
            }

            if (message->has_mmio_write_message()) {
                message->mutable_mmio_write_message()->set_value(new_value);
            } else if (message->has_pio_write_message()) {
                message->mutable_pio_write_message()->set_value(new_value);
            }
        }

        if (message->has_dma_message()) {
            auto* dma_message = message->mutable_dma_message();
            if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
                if (dma_message->has_dma_random_message()) {
                    auto* random_message = dma_message->mutable_dma_random_message();

                    if (random_message->len() > 0) {
                        std::uniform_int_distribution<size_t> byte_dist(0, random_message->len() - 1);
                        size_t byte_index = byte_dist(rng);

                        std::string data = random_message->data();

                        uint8_t original_byte = static_cast<uint8_t>(data[byte_index]);
                        uint8_t mutated_byte = static_cast<uint8_t>(mutateValue(original_byte, rng));
                        data[byte_index] = static_cast<char>(mutated_byte);

                        random_message->set_data(data);
                    }
                }
			} else if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_STRUCTURE) {
				if (dma_message->has_dma_random_message()) {
					auto* structure_message = dma_message->mutable_dma_random_message();
					uint32_t index = structure_message->index();
					const auto& structure = dma_info.structures(index);

					uint32_t start_pos = 0;
					uint32_t end_pos = randomData<uint32_t>(0, structure_message->len() - 1, rng);
					bool is_gen = false;

					uint32_t size = 0;
					std::vector<uint8_t> data;
					processStructure(structure, size, &data, rng, start_pos, end_pos, is_gen);

					assert(start_pos <= end_pos);
					assert(end_pos <= data.size());

					std::vector<uint8_t> existing_data(structure_message->data().begin(), structure_message->data().end());
					std::copy(data.begin() + start_pos, data.begin() + end_pos, existing_data.begin() + start_pos);
					structure_message->set_data(existing_data.data(), existing_data.size());
				}
            } else if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_VIRTIO) {
                if (dma_message->has_dma_virtio_message()) {
                    auto* virtio_message = dma_message->mutable_dma_virtio_message();
                    for (int i = 0; i < virtio_message->virtio_message_size(); ++i) {
                        auto* vmsg = virtio_message->mutable_virtio_message(i);
                        if (vmsg->virtio_direction() == virtfuzz::VIRTIO_OUT) {
                            if (vmsg->has_virtio_out_message()) {
                                auto* out_message = vmsg->mutable_virtio_out_message();
                                if (out_message->len() > 0) {
                                    std::uniform_int_distribution<size_t> byte_dist(0, out_message->len() - 1);
                                    size_t byte_index = byte_dist(rng);

                                    // Get the current data
                                    std::string data = out_message->data();

                                    // Mutate the chosen byte
                                    uint8_t original_byte = static_cast<uint8_t>(data[byte_index]);
                                    uint8_t mutated_byte = static_cast<uint8_t>(mutateValue(original_byte, rng));
                                    data[byte_index] = static_cast<char>(mutated_byte);

                                    // Set the new data
                                    out_message->set_data(data);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void Mutate_ChangeStride(virtfuzz::MessageSequence& message_sequence, std::mt19937& rng) {
    if (message_sequence.messages_size() > 0) {
        std::uniform_int_distribution<int> dist(0, message_sequence.messages_size() - 1);
        int index = dist(rng);
        auto* message = message_sequence.mutable_messages(index);

        if (message->has_dma_message()) {
			auto* dma_message = message->mutable_dma_message();
			if (dma_message->dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
				if (dma_message->has_dma_random_message()) {
					auto* random_message = dma_message->mutable_dma_random_message();
					random_message->set_stride(randomData<uint8_t>(0, 0xFF, rng));
				}
			}
        }
    }
}

Mutator mutators[] = {
    {Mutate_ChangeAddr, "Mutate_ChangeAddr", BASIC_MUTATION},
    {Mutate_ChangeSize, "Mutate_ChangeSize", BASIC_MUTATION},
    {Mutate_ChangeValue, "Mutate_ChangeValue", BASIC_MUTATION},
    {Mutate_ChangeStride, "Mutate_ChangeStride", BASIC_MUTATION},
    {Mutate_InsertMessage, "Mutate_InsertMessage", MESSAGE_INSERTION},
    {Mutate_InsertMessages, "Mutate_InsertMessages", MESSAGE_INSERTION},
    {Mutate_DuplicateMessages, "Mutate_DuplicateMessages", MESSAGE_INSERTION},
    {Mutate_InsertRepeatedMessages, "Mutate_InsertRepeatedMessages", MESSAGE_INSERTION},
    {Mutate_RemoveMessage, "Mutate_RemoveMessage", MESSAGE_REMOVAL},
    {Mutate_RemoveMessages, "Mutate_RemoveMessages", MESSAGE_REMOVAL},
    {Mutate_ShuffleMessages, "Mutate_ShuffleMessages", MESSAGE_REORDERING},
    {Mutate_SwapMessages, "Mutate_SwapMessages", MESSAGE_REORDERING},
    {Mutate_ReplaceMessage, "Mutate_ReplaceMessage", MESSAGE_REORDERING},
};

const double groupWeights[NUM_MUTATOR_GROUPS] = {
    0.4, // BASIC_MUTATION
    0.2, // MESSAGE_INSERTION
    0.2, // MESSAGE_REMOVAL
    0.2, // MESSAGE_REORDERING
};

size_t select_sequence_mutator(std::mt19937& rng) {
    std::discrete_distribution<size_t> groupDist(groupWeights, groupWeights + NUM_MUTATOR_GROUPS);
    MutatorGroup selectedGroup = static_cast<MutatorGroup>(groupDist(rng));

    std::vector<Mutator> filteredMutators;
    std::copy_if(std::begin(mutators), std::end(mutators), std::back_inserter(filteredMutators),
                 [selectedGroup](const Mutator& m) { return m.group == selectedGroup; });

    std::uniform_int_distribution<size_t> mutatorDist(0, filteredMutators.size() - 1);
    size_t index = mutatorDist(rng);
    return std::distance(mutators, std::find_if(std::begin(mutators), std::end(mutators),
                                                [&filteredMutators, index](const Mutator& m) {
                                                    return m.func == filteredMutators[index].func;
                                                }));
}
