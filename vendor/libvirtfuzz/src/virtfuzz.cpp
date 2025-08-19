#include "virtfuzz.h"
#include "generator.h"
#include "mutator.h"
#include "debug.h"
#include "device.h"
#include "common.h"
#include "statistics.h"

#include <iostream>
#include <random>
#include <sstream>
#include <fstream>
#include <thread>

#include <google/protobuf/util/json_util.h>

extern "C" size_t virtfuzzCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    std::mt19937 rng(Seed);

    virtfuzz::MessageSequence message_sequence;

	if (!message_sequence.ParseFromArray(Data, Size)) {
		DEBUG_PRINT("[MUTATION] Failed to parse MessageSequence from Data, generating new data");
		message_sequence.Clear();
		message_sequence = generateMessages(rng);
	} else {
		DEBUG_PRINT("[MUTATION] Data before mutation (size: " << Size << ", maxsize: " << MaxSize << "):" << std::endl << messageSequenceToReadableString(message_sequence));

		size_t mutator_index = select_sequence_mutator(rng);
        mutators[mutator_index].func(message_sequence, rng);

#ifdef STATISTICS
		updateMutatorCounters(mutators[mutator_index].name);
		updateMutatorCounters("Mutate_Total");
#endif
		DEBUG_PRINT("[MUTATION] Applied mutator: " << mutators[mutator_index].name);
	}

    size_t new_size = message_sequence.ByteSizeLong();

    DEBUG_PRINT("[MUTATION] Data after mutation (size: " << new_size << "):" << std::endl << messageSequenceToReadableString(message_sequence));

    if (new_size > MaxSize) {
        DEBUG_PRINT("[MUTATION] Mutated data exceeds MaxSize: " << new_size << "/" << MaxSize);
        return 0;
    }

    message_sequence.SerializeToArray(Data, new_size);
    return new_size;
}

extern "C" size_t virtfuzzCustomCrossOver(const uint8_t *data1, size_t size1,
                                            const uint8_t *data2, size_t size2,
                                            uint8_t *out, size_t max_out_size,
                                            unsigned int seed) {
    std::mt19937 rng(seed);

    virtfuzz::MessageSequence message_sequence1;
    virtfuzz::MessageSequence message_sequence2;

#ifdef STATISTICS
		updateMutatorCounters("Mutate_CrossOver");
#endif

    if (!message_sequence1.ParseFromArray(data1, size1)) {
        DEBUG_PRINT("[CROSSOVER] Failed to parse MessageSequence from data1 (size " << size1 << ")");
		message_sequence1.Clear();
		message_sequence1 = generateMessages(rng);
    }

    if (!message_sequence2.ParseFromArray(data2, size2)) {
        DEBUG_PRINT("[CROSSOVER] Failed to parse MessageSequence from data2 (size " << size2 << ")");
		message_sequence2.Clear();
		message_sequence2= generateMessages(rng);
    }

    DEBUG_PRINT("[CROSSOVER] Data1 before crossover (size: " << message_sequence1.ByteSizeLong() << "):\n" << messageSequenceToReadableString(message_sequence1));
    DEBUG_PRINT("[CROSSOVER] Data2 before crossover (size: " << message_sequence2.ByteSizeLong() << "):\n" << messageSequenceToReadableString(message_sequence2));

    virtfuzz::MessageSequence output_sequence;

    size_t half_size1 = message_sequence1.messages_size() / 2;
    size_t half_size2 = message_sequence2.messages_size() / 2;

    // Take the first half of messages from the first sequence
    for (size_t i = 0; i < half_size1; ++i) {
        *output_sequence.add_messages() = message_sequence1.messages(i);
    }

    // Take the second half of messages from the second sequence
    for (size_t i = half_size2; i < message_sequence2.messages_size(); ++i) {
        *output_sequence.add_messages() = message_sequence2.messages(i);
    }

    size_t new_size = output_sequence.ByteSizeLong();

    DEBUG_PRINT("[CROSSOVER] Data after crossover (size: " << new_size << "):\n" << messageSequenceToReadableString(output_sequence));

    if (new_size > max_out_size) {
        DEBUG_PRINT("[CROSSOVER] Crossover data exceeds max_out_size");
        return 0;
    }

    output_sequence.SerializeToArray(out, new_size);
    return new_size;
}

void fillMessageFromParsed(const virtfuzz::Message &msg, Message &c_msg);

extern "C" size_t get_message_hypercube(size_t random, MessageSequence *message_sequence) {
	std::mt19937 rng(random);
	virtfuzz::MessageSequence parsed_message_sequence;

    size_t num_messages = 1; // Generate one message as specified

    message_sequence->messages = static_cast<Message*>(malloc(num_messages * sizeof(Message)));
    if (!message_sequence->messages) {
        std::cerr << "[GET MESSAGES]: Failed to allocate memory for messages" << std::endl;
        message_sequence->message_count = 0;
        return 0;
    }

	parsed_message_sequence.Clear();
	parsed_message_sequence = generateMessages(rng);

    for (size_t i = 0; i < num_messages; ++i) {
		const virtfuzz::Message &msg = parsed_message_sequence.messages(i);
        Message &c_msg = message_sequence->messages[i];
        fillMessageFromParsed(msg, c_msg);
    }

    message_sequence->message_count = num_messages;
    return num_messages;
}

extern "C" size_t get_message_sequence(const uint8_t *data, size_t size, MessageSequence *message_sequence) {
    virtfuzz::MessageSequence parsed_message_sequence;

    if (!parsed_message_sequence.ParseFromArray(data, size)) {
        DEBUG_PRINT("[GET MESSAGES]: Failed to parse MessageSequence from data");
        std::mt19937 rng(size);
        parsed_message_sequence.Clear();
        parsed_message_sequence = generateMessages(rng);
    }

    size_t num_messages = parsed_message_sequence.messages_size();
    message_sequence->messages = static_cast<Message*>(malloc(num_messages * sizeof(Message)));
    if (!message_sequence->messages) {
        DEBUG_PRINT("[GET MESSAGES]: Failed to allocate memory for messages");
        message_sequence->message_count = 0;
        return 0;
    }

    DEBUG_PRINT("[GET MESSAGES]:\n" << messageSequenceToReadableString(parsed_message_sequence));

    for (size_t i = 0; i < num_messages; ++i) {
        const virtfuzz::Message &msg = parsed_message_sequence.messages(i);
        Message &c_msg = message_sequence->messages[i];
        fillMessageFromParsed(msg, c_msg);
    }

    DEBUG_PRINT("[STATE]: " << get_state());

    message_sequence->message_count = num_messages;
    return num_messages;
}

void fillMessageFromParsed(const virtfuzz::Message &msg, Message &c_msg) {
    memset(&c_msg, 0, sizeof(Message));

    c_msg.type = static_cast<MessageType>(msg.type());
	updateGetCounters("TOTAL");

    switch (msg.type()) {
        case virtfuzz::MMIO_READ:
#ifdef STATISTICS
			updateGetCounters("MMIO_READ");
#endif
            c_msg.message_content.mmio_read_message.region_id = msg.mmio_read_message().region_id();
            c_msg.message_content.mmio_read_message.addr = msg.mmio_read_message().addr();
            c_msg.message_content.mmio_read_message.size = static_cast<DataSize>(msg.mmio_read_message().size());
            break;
        case virtfuzz::MMIO_WRITE:
#ifdef STATISTICS
			updateGetCounters("MMIO_WRITE");
#endif
            c_msg.message_content.mmio_write_message.region_id = msg.mmio_write_message().region_id();
            c_msg.message_content.mmio_write_message.addr = msg.mmio_write_message().addr();
            c_msg.message_content.mmio_write_message.size = static_cast<DataSize>(msg.mmio_write_message().size());
            c_msg.message_content.mmio_write_message.value = msg.mmio_write_message().value();
            break;
        case virtfuzz::PIO_READ:
#ifdef STATISTICS
			updateGetCounters("PIO_READ");
#endif
            c_msg.message_content.pio_read_message.region_id = msg.pio_read_message().region_id();
            c_msg.message_content.pio_read_message.port = msg.pio_read_message().port();
            c_msg.message_content.pio_read_message.size = static_cast<DataSize>(msg.pio_read_message().size());
            break;
        case virtfuzz::PIO_WRITE:
#ifdef STATISTICS
			updateGetCounters("PIO_WRITE");
#endif
            c_msg.message_content.pio_write_message.region_id = msg.pio_write_message().region_id();
            c_msg.message_content.pio_write_message.port = msg.pio_write_message().port();
            c_msg.message_content.pio_write_message.size = static_cast<DataSize>(msg.pio_write_message().size());
            c_msg.message_content.pio_write_message.value = msg.pio_write_message().value();
            break;
        case virtfuzz::DMA: {
            const auto& dma_message = msg.dma_message();
            auto& c_dma = c_msg.message_content.dma_message;

            if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
#ifdef STATISTICS
				updateGetCounters("DMA_NORMAL");
#endif
                c_dma.dma_message_type = DMA_MESSAGE_TYPE_NORMAL;

                const auto& random_message = dma_message.dma_random_message();
                auto& new_random_msg = c_dma.dma_message_content.dma_random_message;

                new_random_msg.index = random_message.index();
                new_random_msg.stride = random_message.stride();
                new_random_msg.len = random_message.len();
                new_random_msg.data = static_cast<uint8_t*>(malloc(new_random_msg.len));

                if (new_random_msg.data == nullptr) {
                    DEBUG_PRINT("[GET MESSAGES]: Failed to allocate memory for random DMA message data");
                    return;
                }

                memcpy(new_random_msg.data, random_message.data().data(), new_random_msg.len);
			} else if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_STRUCTURE) {
#ifdef STATISTICS
				updateGetCounters("DMA_STRUCTURE");
#endif
                c_dma.dma_message_type = DMA_MESSAGE_TYPE_STRUCTURE;

                const auto& random_message = dma_message.dma_random_message();
                auto& new_random_msg = c_dma.dma_message_content.dma_random_message;

                new_random_msg.index = random_message.index();
                new_random_msg.stride = random_message.stride();
                new_random_msg.len = random_message.len();
                new_random_msg.data = static_cast<uint8_t*>(malloc(new_random_msg.len));

                if (new_random_msg.data == nullptr) {
                    DEBUG_PRINT("[GET MESSAGES]: Failed to allocate memory for random DMA message data");
                    return;
                }

                memcpy(new_random_msg.data, random_message.data().data(), new_random_msg.len);
            } else {
#ifdef STATISTICS
				updateGetCounters("DMA_VIRTIO");
#endif
                c_dma.dma_message_type = DMA_MESSAGE_TYPE_VIRTIO;

                const auto& virtio_message = dma_message.dma_virtio_message();
                auto& new_virtio_msg = c_dma.dma_message_content.dma_virtio_message;

                new_virtio_msg.queue_num = virtio_message.queue_num();
                set_state(virtio_message.index());
                uint32_t num_virtio_messages = virtio_message.virtio_message_size();
                new_virtio_msg.size = num_virtio_messages;
                new_virtio_msg.virtio_messages = static_cast<VirtIOMessage*>(malloc(num_virtio_messages * sizeof(VirtIOMessage)));

                if (new_virtio_msg.virtio_messages == nullptr) {
                    DEBUG_PRINT("[GET MESSAGES]: Failed to allocate memory for Virtio DMA messages");
                    return;
                }

                for (uint32_t i = 0; i < num_virtio_messages; ++i) {
                    const auto& proto_virtio_msg = virtio_message.virtio_message(i);
                    auto& c_virtio_msg = new_virtio_msg.virtio_messages[i];

                    c_virtio_msg.virtio_direction = static_cast<VirtIODirection>(proto_virtio_msg.virtio_direction());

                    if (proto_virtio_msg.virtio_messsage_case() == virtfuzz::VirtIOMessage::kVirtioOutMessage) {
                        const auto& out_message = proto_virtio_msg.virtio_out_message();
                        c_virtio_msg.virtio_message.virtio_out_message.len = out_message.len();
                        c_virtio_msg.virtio_message.virtio_out_message.data = static_cast<uint8_t*>(malloc(out_message.data().size()));

                        if (c_virtio_msg.virtio_message.virtio_out_message.data == nullptr) {
                            DEBUG_PRINT("[GET MESSAGES]: Failed to allocate memory for Virtio Out message data");
                            for (uint32_t j = 0; j < i; ++j) {
                                if (new_virtio_msg.virtio_messages[j].virtio_direction == VIRTIO_DIRECTION_OUT) {
                                    free(new_virtio_msg.virtio_messages[j].virtio_message.virtio_out_message.data);
                                }
                            }
                            free(new_virtio_msg.virtio_messages);
                            return;
                        }

                        memcpy(c_virtio_msg.virtio_message.virtio_out_message.data, out_message.data().data(), out_message.data().size());

                    } else if (proto_virtio_msg.virtio_messsage_case() == virtfuzz::VirtIOMessage::kVirtioInMessage) {
                        const auto& in_message = proto_virtio_msg.virtio_in_message();
                        c_virtio_msg.virtio_message.virtio_in_message.len = in_message.len();
                    }
                }
            }
            break;
        }
        default:
            DEBUG_PRINT("[GET MESSAGES]: Unsupported message type");
            return;
    }
}

extern "C" size_t cleanup(MessageSequence *message_sequence) {
    if (message_sequence == nullptr || message_sequence->messages == nullptr) {
        return 1;
    }

    for (size_t i = 0; i < message_sequence->message_count; ++i) {
        Message &msg = message_sequence->messages[i];
        
        switch (msg.type) {
            case MessageType::DMA: {
                DMAMessage &c_dma = msg.message_content.dma_message;
                if (c_dma.dma_message_type == DMA_MESSAGE_TYPE_VIRTIO) {
                    DMAVirtioMessage &virtio_msg = c_dma.dma_message_content.dma_virtio_message;
                    for (size_t j = 0; j < virtio_msg.size; ++j) {
                        VirtIOMessage &virtio_message = virtio_msg.virtio_messages[j];
                        if (virtio_message.virtio_direction == VIRTIO_DIRECTION_OUT) {
                            free(virtio_message.virtio_message.virtio_out_message.data);
                        }
                    }
                    free(virtio_msg.virtio_messages);
                } else if (c_dma.dma_message_type == DMA_MESSAGE_TYPE_NORMAL || c_dma.dma_message_type == DMA_MESSAGE_TYPE_STRUCTURE) {
                    DMARandomMessage &random_msg = c_dma.dma_message_content.dma_random_message;
                    free(random_msg.data);
                }
                break;
            }
            default:
                break;
        }
    }

    free(message_sequence->messages);
    message_sequence->messages = nullptr;
    message_sequence->message_count = 0;

    return 0;
}

int init_dma(const char *file_path) {
    std::string json_file_path = std::string(file_path);
    size_t bin_pos = json_file_path.rfind(".json");
    if (bin_pos != std::string::npos) {
		json_file_path.replace(bin_pos, 5, "_dma.json");
    }

    std::ifstream input(json_file_path, std::ios::binary);
    if (!input) {
        std::cerr << "Failed to open file: " << json_file_path << std::endl;
        return 1;
    }

    std::string json_data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    google::protobuf::util::JsonParseOptions options;
    google::protobuf::Message *message = nullptr;
    if (json_file_path.find("virtio") != std::string::npos) {
        message = &virtio_dma_info;
    } else {
        message = &dma_info;
    }

    auto status = google::protobuf::util::JsonStringToMessage(json_data, message, options);

    if (!status.ok()) {
        std::cerr << "Failed to parse JSON: " << status.ToString() << std::endl;
        return -1;
    }

    if (json_file_path.find("virtio") != std::string::npos) {
        std::cout << "Parsed VIRTIO DMA successfully!" << std::endl;
    } else {
        std::cout << "Parsed DMA successfully!" << std::endl;
    }
    
    // std::cout << "Parsed DMA: " << std::endl;
    // std::cout << message->DebugString() << std::endl;

    return 0;
}

extern "C" int init_device_model(const char *file_path) {
	int result;

	std::cout << "\033[31m";

	result = init_dma(file_path);
	result = init_model(file_path);

	std::cout << "\033[0m";

#ifdef STATISTICS
	start_background_writer(file_path);
#endif

    return result;
}

const char *InterfaceTypeNames[INTERFACE_TYPE_NUM + 1] = {
    "INTERFACE_TYPE_MMIO",
    "INTERFACE_TYPE_PIO",
	"INTERFACE_TYPE_DMA",
    "INTERFACE_TYPE_NUM",
};

std::vector<InterfaceDescription> Interfaces;
std::vector<uint8_t> mmio_region_ids;
std::vector<uint8_t> pio_region_ids;
std::vector<uint8_t> dma_region_ids;

extern "C" int get_number_of_interfaces(void) {
    return Interfaces.size();
}

extern "C" void add_interface(InterfaceType type, uint64_t addr, uint32_t size,
                              const char *name, uint8_t min_access_size, uint8_t max_access_size) {

    for (const auto& iface : Interfaces) {
        if (iface.type == type && iface.addr == addr && iface.size == size) {
            std::cerr << "Interface exists!" << std::endl;
            return;
        }
    }

    if (!strcmp(name, "sparse-mem") || size == 0) {
        return;
    }

    if (type == INTERFACE_TYPE_MMIO) {
        mmio_region_ids.push_back(Interfaces.size());
    } else if (type == INTERFACE_TYPE_PIO) {
        pio_region_ids.push_back(Interfaces.size());
    } else if (type == INTERFACE_TYPE_DMA) {
		dma_region_ids.push_back(Interfaces.size());
	} else {
		std::cerr << "Unknown type!" << std::endl;
		return;
	}

    InterfaceDescription new_interface;
    new_interface.type = type;
    new_interface.addr = addr;
    new_interface.size = size;
    new_interface.min_access_size = min_access_size;
    new_interface.max_access_size = max_access_size;
    strncpy(new_interface.name, name, sizeof(new_interface.name) - 1);
    new_interface.name[sizeof(new_interface.name) - 1] = '\0';

    std::cerr << "New Interface Details:" << std::endl;
    std::cerr << "    Type: " << static_cast<int>(new_interface.type) << std::endl;
    std::cerr << "    Addr: 0x" << std::hex << new_interface.addr << std::dec << std::endl;
    std::cerr << "    Size: " << new_interface.size << std::endl;
    std::cerr << "    Name: " << new_interface.name << std::endl;
    std::cerr << "    Min Access Size: " << static_cast<int>(new_interface.min_access_size) << std::endl;
    std::cerr << "    Max Access Size: " << static_cast<int>(new_interface.max_access_size) << std::endl;

	for (const auto& calleeOrOp : device_model.ops()) {
		if (calleeOrOp.has_operation()) {
			const auto& operation = calleeOrOp.operation();
			if (operation.region_id() != Interfaces.size() || operation.rw() == "R") {
				continue;
			}
			uint64_t addr = operation.reg(0);
			if (addr != 0xdeadc0de && addr != 0xdeadbeef) {
				addr += new_interface.addr;
			}
			auto value = operation.reg_node();
			addr_value_map[addr].emplace_back(value);
		}
	}

    Interfaces.push_back(new_interface);
}

extern "C" void print_interfaces(void) {
	int i = 0;
    for (const auto& ed : Interfaces) {
        std::cerr << "[" << std::dec << (int)i << "] " << ed.name << ", " << InterfaceTypeNames[ed.type]
                  << ", 0x" << std::hex << ed.addr << " +0x" << std::hex << ed.size << std::dec
                  << ", " << static_cast<int>(ed.min_access_size) << "," << static_cast<int>(ed.max_access_size) << std::endl;
		i++;
    }
}
