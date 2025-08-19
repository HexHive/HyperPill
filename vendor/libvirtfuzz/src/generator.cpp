#include "generator.h"
#include "mutator.h"
#include "common.h"
#include "debug.h"
#include "device.h"
#include "device.pb.h"
#include "xhci.h"
#include "ehci.h"
#include "statistics.h"
#include <sstream>

using namespace device;

void appendInt16ToBytes(uint16_t value, std::vector<uint8_t>& data) {
    data.push_back(static_cast<uint8_t>(value & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void appendInt32ToBytes(uint32_t value, std::vector<uint8_t>& data) {
    data.push_back(static_cast<uint8_t>(value & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void appendInt64ToBytes(uint64_t value, std::vector<uint8_t>& data) {
    data.push_back(static_cast<uint8_t>(value & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    data.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
}

void processField(const device::StructureField& field, uint32_t& size, std::vector<uint8_t>* data, std::mt19937 &rng, uint32_t &start_pos, uint32_t &end_pos, bool &is_gen) {
    auto chooseFromValues = [&](auto min, auto max) -> decltype(min) {
        if (field.values_size() > 0) {
            std::uniform_int_distribution<size_t> dist(0, field.values_size() - 1);
            return static_cast<uint32_t>(field.values(dist(rng)));
        } else {
            return randomData<decltype(min)>(min, max, rng);
        }
    };

    auto chooseFromFlagMask = [&](uint32_t &result) {
        if (field.flag_mask_size() > 0) {
            std::uniform_int_distribution<size_t> dist(1, (1 << field.flag_mask_size()) - 1);
            size_t combination = dist(rng);
            result = 0;
            for (size_t i = 0; i < field.flag_mask_size(); ++i) {
                if (combination & (1 << i)) {
                    result |= (1 << field.flag_mask(i));
                }
            }
        }
    };

    auto shouldApplyMasks = [&](std::mt19937 &rng) -> bool {
        std::uniform_int_distribution<int> dist(0, 99);
        return dist(rng) < 90;
    };

    switch (field.value_case()) {
        case device::StructureField::kFieldType: {
            switch (field.field_type()) {
                case device::UINT8: {
                    uint8_t intValue;
                    if (shouldApplyMasks(rng)) {
                        intValue = chooseFromValues(static_cast<uint8_t>(0), static_cast<uint8_t>(0xFF));
                        if (field.flag_mask_size() > 0) {
                            uint32_t flagValue;
                            chooseFromFlagMask(flagValue);
                            intValue = static_cast<uint8_t>(flagValue);
                        }
                        if (field.has_mod_mask()) {
                            intValue %= field.mod_mask();
                        }
                        if (field.has_int_mask()) {
                            intValue &= field.int_mask();
                        }
                    } else {
                        intValue = randomData<uint8_t>(0, 0xFF, rng);
                    }
					if (!is_gen && size + 1 >= end_pos) {
						start_pos = size;
						end_pos = size + 1;
						is_gen = true;
					}
                    size += 1;
                    if (data) {
                        data->push_back(intValue);
                    }
                    break;
                }
                case device::UINT16: {
                    uint16_t intValue;
                    if (shouldApplyMasks(rng)) {
                        intValue = chooseFromValues(static_cast<uint16_t>(0), static_cast<uint16_t>(0xFFFF));
                        if (field.flag_mask_size() > 0) {
                            uint32_t flagValue;
                            chooseFromFlagMask(flagValue);
                            intValue = static_cast<uint16_t>(flagValue);
                        }
                        if (field.has_mod_mask()) {
                            intValue %= field.mod_mask();
                        }
                        if (field.has_int_mask()) {
                            intValue &= field.int_mask();
                        }
						if (field.has_or_mask()) {
							intValue |= field.or_mask();
						}
                    } else {
                        intValue = randomData<uint16_t>(0, 0xFFFF, rng);
                    }
					if (!is_gen && size + 2 >= end_pos) {
						start_pos = size;
						end_pos = size + 2;
						is_gen = true;
					}
                    size += 2;
                    if (data) {
                        appendInt16ToBytes(intValue, *data);
                    }
                    break;
                }
                case device::UINT32: {
                    uint32_t intValue;
                    if (shouldApplyMasks(rng)) {
                        intValue = chooseFromValues(static_cast<uint32_t>(0), static_cast<uint32_t>(0xFFFFFFFF));
                        if (field.flag_mask_size() > 0) {
                            chooseFromFlagMask(intValue);
                        }
                        if (field.has_mod_mask()) {
                            intValue %= field.mod_mask();
                        }
                        if (field.has_int_mask()) {
                            intValue &= field.int_mask();
                        }
						if (field.has_or_mask()) {
							intValue |= field.or_mask();
						}
						if (!field.name().compare("hw_info1") || !field.name().compare("hw_fullspeed_ep")) {
							int choice = randomData<uint8_t>(0, 99, rng);
							int value;
							if (choice < 50) {
								value = 0x81;	
							} else {
								value = 0x02;
							}
							intValue &= ~0xf00;
							intValue |= (value << 8);
							intValue &= ~0x3f;
							intValue |= 0x03;
						} else if (!field.name().compare("hw_bufp1")) {
							int choice = randomData<uint8_t>(0, 99, rng);
							int value;
							if (choice < 50) {
								value = 0x81;	
							} else {
								value = 0x02;
							}
							intValue &= ~0xf00;
							intValue |= (value << 8);
							intValue &= ~0x07;
							intValue |= 0x03;
						}
                    } else {
                        intValue = randomData<uint32_t>(0, 0xFFFFFFFF, rng);
                    }
					if (!is_gen && size + 4 >= end_pos) {
						start_pos = size;
						end_pos = size + 4;
						is_gen = true;
					}
                    size += 4;
                    if (data) {
                        appendInt32ToBytes(intValue, *data);
                    }
                    break;
                }
                case device::UINT64: {
                    uint64_t intValue;
                    if (shouldApplyMasks(rng)) {
                        intValue = chooseFromValues(static_cast<uint64_t>(0), static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF));
                        if (field.flag_mask_size() > 0) {
                            uint32_t flagValue;
                            chooseFromFlagMask(flagValue);
                            intValue = static_cast<uint64_t>(flagValue);
                        }
                        if (field.has_mod_mask()) {
                            intValue %= field.mod_mask();
                        }
                        if (field.has_int_mask()) {
                            intValue &= field.int_mask();
                        }
						if (field.has_or_mask()) {
							intValue |= field.or_mask();
						}
						if (!field.name().compare("plug_addr")) {
							intValue = intValue & 0xfffffff;
							intValue = intValue / 0x200000 * 0x200000;
							intValue += 0x100000000;
						}
                    } else {
                        intValue = randomData<uint64_t>(0, 0xFFFFFFFFFFFFFFFF, rng);
                    }
					if (!is_gen && size + 8 >= end_pos) {
						start_pos = size;
						end_pos = size + 8;
						is_gen = true;
					}
                    size += 8;
                    if (data) {
                        appendInt64ToBytes(intValue, *data);
                    }
                    break;
                }
                case device::SIZE: {
                    uint32_t sizeIncrement = chooseFromValues(static_cast<uint32_t>(1), static_cast<uint32_t>(0xFF));
					if (!is_gen) {
						assert(false);
					}
                    size += sizeIncrement;
                    if (data) {
                        for (uint32_t i = 0; i < sizeIncrement; ++i) {
                            data->push_back(randomData<uint8_t>(0, 0xFF, rng));
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            break;
        }
        case device::StructureField::kStructure: {
            processStructure(field.structure(), size, data, rng, start_pos, end_pos, is_gen);
            break;
        }
        default:
            break;
    }
}

void processStructure(const device::Structure& structure, uint32_t& size, std::vector<uint8_t>* data, std::mt19937 &rng, uint32_t &start_pos, uint32_t &end_pos, bool &is_gen) {
	if (!structure.name().compare("xhci_generic_trb")) {
		struct xhci_generic_trb {
			uint32_t field[4];
		};
		xhci_generic_trb trb;

		for (uint8_t i = 0; i < 4; ++i) {
			trb.field[i] = randomData<uint32_t>(0, 0xFFFFFFFF, rng);
		}

		uint32_t type = TRB_FIELD_TO_TYPE(trb.field[3]) % 50;
		uint8_t slot_id = TRB_TO_SLOT_ID(trb.field[3]) % 12;
		// uint8_t ep_id = TRB_TO_EP_INDEX(trb.field[3]);
		uint8_t port_id = TRB_TO_SUSPEND_PORT(trb.field[0]) & 0x7;
		uint16_t stream_id = TRB_TO_STREAM_ID(trb.field[2]) & 0x1;
		trb.field[3] &= ~0xfc00;
		trb.field[3] |= (type << 10);

		if (type == TRB_TRANSFER || type == TRB_COMPLETION || type == TRB_BANDWIDTH_EVENT || type == TRB_DOORBELL ||
			type == TRB_DEV_NOTE || type == TRB_ENABLE_SLOT || type == TRB_DISABLE_SLOT || type == TRB_ADDR_DEV ||
			type == TRB_CONFIG_EP || type == TRB_EVAL_CONTEXT || type == TRB_RESET_EP || type == TRB_STOP_RING ||
			type == TRB_SET_DEQ || type == TRB_RESET_DEV || type == TRB_GET_BW) {
			trb.field[3] &= ~SLOT_ID_FOR_TRB(0xff);
			trb.field[3] |= SLOT_ID_FOR_TRB(slot_id);
		}

		if (type == TRB_TRANSFER || type == TRB_RESET_EP || type == TRB_STOP_RING || type == TRB_SET_DEQ) {
			trb.field[3] &= ~EP_ID_FOR_TRB(0x1e);
			trb.field[3] |= EP_ID_FOR_TRB(randomChoice<uint8_t>({0x1, 0x2, 0x3, 0x80, 0x81, 0x82}, rng));
		}

		if (type == TRB_PORT_STATUS) {
			trb.field[0] &= ~SUSPEND_PORT_FOR_TRB(1);
			trb.field[0] |= SUSPEND_PORT_FOR_TRB(port_id);
		}

		if (type == TRB_SET_DEQ) {
			trb.field[2] &= ~STREAM_ID_FOR_TRB(0xffff);
			trb.field[2] |= STREAM_ID_FOR_TRB(stream_id);
		}

		for (int i = 0; i < 4; ++i) {
			appendInt32ToBytes(trb.field[i], *data);
		}
		size += sizeof(trb);
		
		if (!is_gen) {
			start_pos = 0;
			end_pos = size;
		}
	} else {
		for (const auto& field : structure.fields()) {
			processField(field, size, data, rng, start_pos, end_pos, is_gen);
		}
	}
}

void generateRandomDMAMessage(virtfuzz::Message& message, std::mt19937& rng) {
#ifdef STATISTICS
	updateCounters("DMA_RANDOM");
	updateCounters("RANDOM");
#endif
    auto* dma_message = message.mutable_dma_message();
	dma_message->set_dma_message_type(virtfuzz::DMA_MESSAGE_NORMAL);

    auto* dma_random_message = dma_message->mutable_dma_random_message();
    dma_random_message->set_index(randomData<uint8_t>(0, 0xFF, rng));
    dma_random_message->set_stride(randomData<uint8_t>(0, 0xFF, rng));
    dma_random_message->set_len(randomData<uint16_t>(1, 0xFF, rng));

    std::vector<uint8_t> data(dma_random_message->len());
    for (auto& byte : data) {
        byte = randomData<uint8_t>(0, 0xFF, rng);
    }

    dma_random_message->set_data(data.data(), data.size());
}

void generateDMAMessage(virtfuzz::Message& message, std::mt19937 &rng) {
    message.set_type(virtfuzz::DMA);
    auto* dma_message = message.mutable_dma_message();
	uint32_t start_pos = 0, end_pos = 0;
	bool is_gen = true;

#ifdef STATISTICS
	updateCounters("DMA");
#endif

	if (isVirtIODMAInitialized()) {
#ifdef STATISTICS
		updateCounters("DMA_VIRTIO");
		updateCounters("MODEL");
#endif
		dma_message->set_dma_message_type(virtfuzz::DMA_MESSAGE_VIRTIO);

		if (!virtio_dma_info.virtio_dma().empty()) {
			size_t chosen_index = randomData<size_t>(0, virtio_dma_info.virtio_dma_size() - 1, rng);

			const auto& virtio_dma = virtio_dma_info.virtio_dma(chosen_index);
			auto* dma_virtio_message = dma_message->mutable_dma_virtio_message();
			dma_virtio_message->set_queue_num(virtio_dma.queue_num());
			dma_virtio_message->set_index(chosen_index);

			for (const auto& structure : virtio_dma.structures()) {
				auto* virtio_message = dma_virtio_message->add_virtio_message();
				virtio_message->set_virtio_direction(static_cast<virtfuzz::VirtIODiection>(structure.virtio_direction()));
				
				if (structure.virtio_direction() == device::VirtIODiection::VIRTIO_OUT) {
					uint32_t size = 0;
					std::vector<uint8_t> data;

					processStructure(structure, size, &data, rng, start_pos, end_pos, is_gen);

					auto* out_message = virtio_message->mutable_virtio_out_message();
					out_message->set_len(size);
					out_message->set_data(data.data(), data.size());
				} else if (structure.virtio_direction() == device::VirtIODiection::VIRTIO_IN) {
					uint32_t size = 0;

					processStructure(structure, size, nullptr, rng, start_pos, end_pos, is_gen); // Only calculate the size

					auto* in_message = virtio_message->mutable_virtio_in_message();
					in_message->set_len(size);
				}
			}
		}
    } else if (isDMAInitialized()) {
#ifdef STATISTICS
		updateCounters("DMA_STRUCTURE");
		updateCounters("MODEL");
#endif
        std::uniform_int_distribution<int> dist(0, 99);
        int chance = dist(rng);

        if (chance < 90 && !dma_info.structures().empty()) {
			dma_message->set_dma_message_type(virtfuzz::DMA_MESSAGE_STRUCTURE);

            const auto& predefinedStructures = dma_info.structures();
            size_t chosenIndex = randomData<size_t>(0, predefinedStructures.size() - 1, rng);
            const auto& chosenStructure = predefinedStructures[chosenIndex];

            uint32_t size = 0;
            std::vector<uint8_t> data;
            processStructure(chosenStructure, size, &data, rng, start_pos, end_pos, is_gen);

            auto* dma_random_message = dma_message->mutable_dma_random_message();
            dma_random_message->set_index(chosenStructure.index());
            dma_random_message->set_stride(0);
            dma_random_message->set_len(size);
            dma_random_message->set_data(data.data(), data.size());
        } else {
            generateRandomDMAMessage(message, rng);
        }
    } else {
        generateRandomDMAMessage(message, rng);
    }
}

virtfuzz::Message generateMessageRandom(std::mt19937 &rng, bool is_dma) {
    virtfuzz::Message message;
    std::vector<uint8_t> available_message_types;
    std::vector<uint32_t> weights;

    if (is_dma) {
        if (!dma_region_ids.empty()) {
            available_message_types.push_back(virtfuzz::DMA);
            weights.push_back(Interfaces[dma_region_ids[0]].size); // Assume one DMA region
        }
    } else {
        uint32_t total_mmio_size = 0, total_pio_size = 0;
        for (const auto& id : mmio_region_ids) {
            total_mmio_size += Interfaces[id].size;
        }
        for (const auto& id : pio_region_ids) {
            total_pio_size += Interfaces[id].size;
        }

        if (total_mmio_size > 0) {
            available_message_types.push_back(virtfuzz::MMIO_WRITE);
            available_message_types.push_back(virtfuzz::MMIO_READ);

            uint32_t mmio_write_weight = static_cast<uint32_t>(total_mmio_size * 0.8);
            uint32_t mmio_read_weight = static_cast<uint32_t>(total_mmio_size * 0.2);

            if (total_pio_size > 0) {
                mmio_write_weight = std::min(mmio_write_weight, total_pio_size * 100);
                mmio_read_weight = std::min(mmio_read_weight, total_pio_size * 100);
            }

            weights.push_back(mmio_write_weight);
            weights.push_back(mmio_read_weight);
        }

        if (total_pio_size > 0) {
            available_message_types.push_back(virtfuzz::PIO_WRITE);
            available_message_types.push_back(virtfuzz::PIO_READ);

            uint32_t pio_write_weight = static_cast<uint32_t>(total_pio_size * 0.8);
            uint32_t pio_read_weight = static_cast<uint32_t>(total_pio_size * 0.2);

            weights.push_back(pio_write_weight);
            weights.push_back(pio_read_weight);
        }
    }

	assert(!available_message_types.empty());

	std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
    uint8_t message_type = available_message_types[dist(rng)];

    switch (message_type) {
        case virtfuzz::MMIO_READ: {
			assert(!mmio_region_ids.empty());

            message.set_type(virtfuzz::MMIO_READ);
            auto* mmio_read = message.mutable_mmio_read_message();
            uint8_t region_id = mmio_region_ids[randomData<size_t>(0, mmio_region_ids.size() - 1, rng)];
            mmio_read->set_region_id(region_id);
            const InterfaceDescription &iface = Interfaces[region_id];
            mmio_read->set_addr(randomData<uint32_t>(iface.addr, iface.addr + iface.size - 1, rng));
            mmio_read->set_size(getRandomDataSize(rng, false));

#ifdef STATISTICS
			updateCounters("MMIO_READ_RANDOM");
			updateCounters("MMIO_READ");
			updateCounters("RANDOM");
#endif

            break;
        }
        case virtfuzz::MMIO_WRITE: {
			assert(!mmio_region_ids.empty());

            message.set_type(virtfuzz::MMIO_WRITE);
            auto* mmio_write = message.mutable_mmio_write_message();
            uint8_t region_id = mmio_region_ids[randomData<size_t>(0, mmio_region_ids.size() - 1, rng)];
            mmio_write->set_region_id(region_id);
            const InterfaceDescription &iface = Interfaces[region_id];
            mmio_write->set_addr(randomData<uint32_t>(iface.addr, iface.addr + iface.size - 1, rng));
            mmio_write->set_size(getRandomDataSize(rng, false));
            mmio_write->set_value(randomData<uint32_t>(0, 0xFFFFFFFF, rng));

#ifdef STATISTICS
			updateCounters("MMIO_WRITE_RANDOM");
			updateCounters("MMIO_WRITE");
			updateCounters("RANDOM");
#endif

            break;
        }
        case virtfuzz::PIO_READ: {
			assert(!pio_region_ids.empty());

            message.set_type(virtfuzz::PIO_READ);
            auto* pio_read = message.mutable_pio_read_message();
            uint8_t region_id = pio_region_ids[randomData<size_t>(0, pio_region_ids.size() - 1, rng)];
            pio_read->set_region_id(region_id);
            const InterfaceDescription &iface = Interfaces[region_id];
            pio_read->set_port(randomData<uint32_t>(iface.addr, iface.addr + iface.size - 1, rng));
            pio_read->set_size(getRandomDataSize(rng, true));

#ifdef STATISTICS
			updateCounters("PIO_READ_RANDOM");
			updateCounters("PIO_READ");
			updateCounters("RANDOM");
#endif

            break;
        }
        case virtfuzz::PIO_WRITE: {
			assert(!pio_region_ids.empty());

            message.set_type(virtfuzz::PIO_WRITE);
            auto* pio_write = message.mutable_pio_write_message();
            uint8_t region_id = pio_region_ids[randomData<size_t>(0, pio_region_ids.size() - 1, rng)];
            pio_write->set_region_id(region_id);
            const InterfaceDescription &iface = Interfaces[region_id];
            pio_write->set_port(randomData<uint32_t>(iface.addr, iface.addr + iface.size - 1, rng));
            pio_write->set_size(getRandomDataSize(rng, true));
            pio_write->set_value(randomData<uint32_t>(0, 0xFFFFFFFF, rng));

#ifdef STATISTICS
			updateCounters("PIO_WRITE_RANDOM");
			updateCounters("PIO_WRITE");
			updateCounters("RANDOM");
#endif

            break;
        }
		case virtfuzz::DMA: {
			assert(!dma_region_ids.empty());

			generateDMAMessage(message, rng);
			break;
		}
        default:
            break;
    }

    DEBUG_PRINT("[GENERATION RANDOM] " << messageToReadableString(message));

    return message;
}

uint64_t evaluateIntraDepNode(const IntraDepNode &node, std::mt19937 &rng, std::unordered_map<uint64_t, uint64_t>& common_values) {
    uint64_t result;
    switch (node.node_value_type()) {
        case IntraDepNodeValueType::k_NODE_VALUE_CONSTANT:
            result = node.value();
            DEBUG_PRINT("evaluateIntraDepNode: Constant value: 0x" << std::hex << result);
            break;
        case IntraDepNodeValueType::k_NODE_VALUE_ADD: {
            if (node.children_size() != 2) throw std::runtime_error("ADD node must have exactly 2 children");
            uint64_t left = evaluateIntraDepNode(node.children(0), rng, common_values);
            uint64_t right = evaluateIntraDepNode(node.children(1), rng, common_values);
            result = left + right;
            DEBUG_PRINT("evaluateIntraDepNode: ADD: 0x" << std::hex << left << " + 0x" << right << " = 0x" << result);
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_AND: {
            if (node.children_size() != 2) throw std::runtime_error("AND node must have exactly 2 children");
            uint64_t left = evaluateIntraDepNode(node.children(0), rng, common_values);
            uint64_t right = evaluateIntraDepNode(node.children(1), rng, common_values);
            result = left & right;
            DEBUG_PRINT("evaluateIntraDepNode: AND: 0x" << std::hex << left << " & 0x" << right << " = 0x" << result);
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_OR: {
            if (node.children_size() != 2) throw std::runtime_error("OR node must have exactly 2 children");
            uint64_t left = evaluateIntraDepNode(node.children(0), rng, common_values);
            uint64_t right = evaluateIntraDepNode(node.children(1), rng, common_values);
            result = left | right;
            DEBUG_PRINT("evaluateIntraDepNode: OR: 0x" << std::hex << left << " | 0x" << right << " = 0x" << result);
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_SHL: {
            if (node.children_size() != 2) throw std::runtime_error("SHL node must have exactly 2 children");
            uint64_t left = evaluateIntraDepNode(node.children(0), rng, common_values);
            uint64_t right = evaluateIntraDepNode(node.children(1), rng, common_values);
            result = left << right;
            DEBUG_PRINT("evaluateIntraDepNode: SHL: 0x" << std::hex << left << " << 0x" << right << " = 0x" << result);
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_LSHR: {
            if (node.children_size() != 2) throw std::runtime_error("LSHR node must have exactly 2 children");
            uint64_t left = evaluateIntraDepNode(node.children(0), rng, common_values);
            uint64_t right = evaluateIntraDepNode(node.children(1), rng, common_values);
            result = left >> right;
            DEBUG_PRINT("evaluateIntraDepNode: LSHR: 0x" << std::hex << left << " >> 0x" << right << " = 0x" << result);
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_COMMON: {
            auto it = common_values.find(node.var_cnt());
            if (it != common_values.end()) {
                result = it->second;
                DEBUG_PRINT("evaluateIntraDepNode: COMMON: var_cnt " << std::dec << node.var_cnt() << " = 0x" << std::hex << result);
            } else {
                throw std::runtime_error("No matching var_cnt found for COMMON node");
            }
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_PHI:
        case IntraDepNodeValueType::k_NODE_VALUE_SELECT:
        case IntraDepNodeValueType::k_NODE_VALUE_ARG: {
            if (node.children_size() > 0) {
                std::vector<uint64_t> results;
                results.reserve(node.children_size());
                for (int i = 0; i < node.children_size(); ++i) {
                    results.push_back(evaluateIntraDepNode(node.children(i), rng, common_values));
                }
                std::uniform_int_distribution<std::size_t> dist(0, results.size() - 1);
                result = results[dist(rng)];
                DEBUG_PRINT("evaluateIntraDepNode: PHI/SELECT/ARG: calculated all children and selected result = 0x" << std::hex << result);
            } else {
                throw std::runtime_error("No children to select from.");
            }
            break;
        }
        case IntraDepNodeValueType::k_NODE_VALUE_CALL:
        case IntraDepNodeValueType::k_NODE_VALUE_NUM_TYPE:
            result = randomData<uint64_t>(0, 0xFFFFFFFFFFFFFFFF, rng);
            DEBUG_PRINT("evaluateIntraDepNode: CALL/NUM_TYPE: random result = 0x" << std::hex << result);
            break;
        default:
            throw std::runtime_error("Unknown node type!");
    }

    common_values[node.var_cnt()] = result;

	std::cout << std::dec;

    return result;
}

virtfuzz::Message generateMessageFromOp(const Operation &operation, std::mt19937 &rng) {
    virtfuzz::Message message;

    if (operation.type() == "MMIO") {
        uint8_t region_id = operation.region_id() % Interfaces.size();
        
        // Ensure the region_id matches the interface type
        while (Interfaces[region_id].type != INTERFACE_TYPE_MMIO) {
            region_id = (region_id + 1) % Interfaces.size();
        }

        const InterfaceDescription &iface = Interfaces[region_id];

        uint32_t addr = operation.reg(0);
        if (addr == 0xdeadbeef || addr == 0xdeadc0de) {
            addr = randomData<uint32_t>(0, iface.size - 1, rng);
        }
        if (operation.rw() == "R") {
            message.set_type(virtfuzz::MMIO_READ);
            auto* mmio_read = message.mutable_mmio_read_message();
            mmio_read->set_region_id(region_id);
            mmio_read->set_addr(iface.addr + (addr % iface.size));
            mmio_read->set_size(static_cast<virtfuzz::DataSize>(operation.size()));
        } else if (operation.rw() == "W") {
            message.set_type(virtfuzz::MMIO_WRITE);
            auto* mmio_write = message.mutable_mmio_write_message();
            mmio_write->set_region_id(region_id);
            mmio_write->set_addr(iface.addr + (addr % iface.size));
            mmio_write->set_size(static_cast<virtfuzz::DataSize>(operation.size()));
            if (!operation.reg().empty()) {
                std::unordered_map<uint64_t, uint64_t> common_values;
                mmio_write->set_value(evaluateIntraDepNode(operation.reg_node(), rng, common_values));
            }
        } else {
            std::cerr << "Error: Unsupported RW type for MMIO operation: " << operation.rw() << "\n";
            return message; // Return an empty message
        }

    } else if (operation.type() == "PIO") {
        uint8_t region_id = operation.region_id() % Interfaces.size();
        
        // Ensure the region_id matches the interface type
        while (Interfaces[region_id].type != INTERFACE_TYPE_PIO) {
            region_id = (region_id + 1) % Interfaces.size();
        }

        const InterfaceDescription &iface = Interfaces[region_id];

        uint32_t port = operation.reg(0);
        if (port == 0xdeadbeef || port == 0xdeadc0de) {
            port = randomData<uint32_t>(0, 0xFFFF, rng); // PIO ports are typically 16-bit
        }
        if (operation.rw() == "R") {
            message.set_type(virtfuzz::PIO_READ);
            auto* pio_read = message.mutable_pio_read_message();
            pio_read->set_region_id(region_id);
            pio_read->set_port(iface.addr + (port % iface.size));
            pio_read->set_size(static_cast<virtfuzz::DataSize>(operation.size()));
        } else if (operation.rw() == "W") {
            message.set_type(virtfuzz::PIO_WRITE);
            auto* pio_write = message.mutable_pio_write_message();
            pio_write->set_region_id(region_id);
            pio_write->set_port(iface.addr + (port % iface.size));
            pio_write->set_size(static_cast<virtfuzz::DataSize>(operation.size()));
            if (!operation.reg().empty()) {
                std::unordered_map<uint64_t, uint64_t> common_values;
                pio_write->set_value(evaluateIntraDepNode(operation.reg_node(), rng, common_values));
            }
        } else {
            std::cerr << "Error: Unsupported RW type for PIO operation: " << operation.rw() << "\n";
            return message; // Return an empty message
        }

    } else {
        DEBUG_PRINT("Error: Unknown operation type: " << operation.type() << "\n");
        message = generateMessageRandom(rng, false);
    }

    DEBUG_PRINT("[GENERATION OP] " << messageToReadableString(message));

    return message;
}

virtfuzz::MessageSequence generateMessagesFromFunctionPaths(const std::string& func_name, std::mt19937& rng) {
    virtfuzz::MessageSequence message_sequence;

    if (device_model.funcs().count(func_name)) {
        const auto& paths_map = device_model.funcs().at(func_name).paths();

        // Get the keys of the paths map to randomly select one
        std::vector<int> path_keys;
        for (const auto& path_item : paths_map) {
            path_keys.push_back(path_item.first);
        }

        if (!path_keys.empty()) {
            int random_path_index = randomData(0, static_cast<int>(path_keys.size()) - 1, rng);
            int selected_path = path_keys[random_path_index];
            const std::string& bb_sequence = paths_map.at(selected_path);

#ifdef STATISTICS
			updateOPCounters("FUNC_" + func_name + "_" + std::to_string(selected_path));
			updateOPCounters("TOTAL_FUNC");
#endif

            std::istringstream bb_stream(bb_sequence);
            std::string bb_id;
            std::ostringstream oss;

            // Iterate over each bb in the selected path and generate messages
            while (bb_stream >> bb_id) {
                std::string bb_key = func_name + "_" + bb_id;
                virtfuzz::MessageSequence path_message_sequence = generateMessagesFromBBKey(bb_key, rng);
                for (const auto& message : path_message_sequence.messages()) {
                    *message_sequence.add_messages() = message;
                }
                oss << bb_key << " ";
            }

            DEBUG_PRINT("[GENERATION FUNC] BBs: " << oss.str());
        } else {
            DEBUG_PRINT("[GENERATION FUNC] No paths found for function: " << func_name);
        }
    } else {
        DEBUG_PRINT("[GENERATION FUNC] No function found for: " << func_name);
    }

    return message_sequence;
}

virtfuzz::MessageSequence generateMessagesFromCallee(const Callee& callee, std::mt19937& rng) {
    return generateMessagesFromFunctionPaths(callee.name(), rng);
}

virtfuzz::MessageSequence generateMessagesFromOpKey(const device::CalleeOrOp &calleeOrOp, std::mt19937 &rng) {
    virtfuzz::MessageSequence message_sequence;

    DEBUG_PRINT("[GENERATION OP " << calleeOrOp.id() << "]");

    if (calleeOrOp.has_operation()) {
        *message_sequence.add_messages() = generateMessageFromOp(calleeOrOp.operation(), rng);
    } else if (calleeOrOp.has_callee()) {
        message_sequence = generateMessagesFromCallee(calleeOrOp.callee(), rng);
    } else {
        throw std::runtime_error("CalleeOrOp is neither an Operation nor a Callee");
    }

    return message_sequence;
}

virtfuzz::MessageSequence generateMessagesFromOps(std::mt19937 &rng) {
    int index = randomData<int>(0, device_model.ops_size() - 1, rng);
    const auto &calleeOrOp = device_model.ops(index);

#ifdef STATISTICS
	updateOPCounters("OP_" + std::to_string(index));
	updateOPCounters("TOTAL_OP");
#endif

	DEBUG_PRINT("[GENERATION FROM OPS]");

    return generateMessagesFromOpKey(calleeOrOp, rng);
}

virtfuzz::MessageSequence generateMessagesFromBBKey(const std::string& bb_key, std::mt19937 &rng) {
    virtfuzz::MessageSequence message_sequence;
    std::ostringstream oss;

    auto bb_it = device_model.bb().find(bb_key);
    if (bb_it != device_model.bb().end()) {
        const std::string& ops_str = bb_it->second;
        std::vector<int> operation_ids;
        std::istringstream value_stream(ops_str);
        std::string operation_id_str;

        while (value_stream >> operation_id_str) {
            int operation_id = std::stoi(operation_id_str);
            operation_ids.push_back(operation_id);
            const auto& calleeOrOp = device_model.ops(operation_id - 1);  // Assumes device_model is accessible here
            
            virtfuzz::MessageSequence generated_sequence = generateMessagesFromOpKey(calleeOrOp, rng);
            for (const auto& message : generated_sequence.messages()) {
                *message_sequence.add_messages() = message;
            }
        }

        oss << bb_key << ", ";
        for (int id : operation_ids) {
            oss << id << " ";
        }

        bb_operation_ids[std::hash<std::string>{}(bb_key)] = operation_ids;
        DEBUG_PRINT("[GENERATION BB] OPs: " << oss.str());
    }

    return message_sequence;
}

virtfuzz::MessageSequence generateMessagesFromDeviceBBs(std::mt19937 &rng) {
    virtfuzz::MessageSequence message_sequence;

    if (device_model.bb_size()) {
        // Get the keys of the bb map to randomly select one
        std::vector<std::string> bb_keys;
        for (const auto& bb_item : device_model.bb()) {
            bb_keys.push_back(bb_item.first);
        }

        int random_index = randomData(0, static_cast<int>(bb_keys.size()) - 1, rng);
        const std::string& selected_key = bb_keys[random_index];

#ifdef STATISTICS
		updateOPCounters("BB_" + selected_key);
		updateOPCounters("TOTAL_BB");
#endif

        message_sequence = generateMessagesFromBBKey(selected_key, rng);
    }

	DEBUG_PRINT("[GENERATION FROM BBS]");

    return message_sequence;
}

virtfuzz::MessageSequence generateMessagesFromDeviceFuncs(std::mt19937& rng) {
    virtfuzz::MessageSequence message_sequence;

    if (device_model.funcs_size()) {
        std::vector<std::string> func_keys;
        for (const auto& func_item : device_model.funcs()) {
            func_keys.push_back(func_item.first);
        }

        int random_func_index = randomData(0, static_cast<int>(func_keys.size()) - 1, rng);
        const std::string& selected_func = func_keys[random_func_index];

        message_sequence = generateMessagesFromFunctionPaths(selected_func, rng);
    }

	DEBUG_PRINT("[GENERATION FROM FUNCS]");

    return message_sequence;
}

virtfuzz::MessageSequence generateMessagesRandom(std::mt19937 &rng) {
    virtfuzz::MessageSequence message_sequence;

    size_t random_num_messages = randomData<size_t>(1, 10, rng);

    for (size_t i = 0; i < random_num_messages; ++i) {
        *message_sequence.add_messages() = generateMessageRandom(rng, false);
    }

	DEBUG_PRINT("[GENERATION MESSAGES RANDOM]:" << random_num_messages);

    return message_sequence;
}

void addMessagesFromSequence(virtfuzz::MessageSequence& target_sequence, const virtfuzz::MessageSequence& source_sequence) {
    for (const auto& message : source_sequence.messages()) {
#ifdef STATISTICS
		updateCounters("TOTAL");
#endif
        *target_sequence.add_messages() = message;
    }
}

virtfuzz::MessageSequence generateMessages(std::mt19937 &rng) {
    virtfuzz::MessageSequence message_sequence;

    int dma_choice = randomData<int>(0, 99, rng);
    if (dma_choice < 15) {
#ifdef STATISTICS
		updateCounters("TOTAL");
#endif
		*message_sequence.add_messages() = generateMessageRandom(rng, true);
    }

    if (isDeviceInitialized()) {
        int choice = randomData<int>(0, 99, rng);

        if (choice < 30) {
            addMessagesFromSequence(message_sequence, generateMessagesFromDeviceFuncs(rng));
        } else if (choice < 60) {
            addMessagesFromSequence(message_sequence, generateMessagesFromDeviceBBs(rng));
        } else if (choice < 80) {
            addMessagesFromSequence(message_sequence, generateMessagesFromOps(rng));
        } else {
            addMessagesFromSequence(message_sequence, generateMessagesRandom(rng));
        }
    } else {
        addMessagesFromSequence(message_sequence, generateMessagesRandom(rng));
    }

	DEBUG_PRINT("[GENERATION MESSAGES]");

    return message_sequence;
}

virtfuzz::Message generateMessage(std::mt19937 &rng) {
    virtfuzz::Message message;
    int io_choice = randomData<int>(0, 99, rng);

#ifdef STATISTICS
	updateCounters("TOTAL");
#endif

    if (io_choice < 85) {
        if (isDeviceInitialized()) {
            int choice = randomData<int>(0, 99, rng);
            if (choice < 80) {
                bool valid_message_generated = false;
                while (!valid_message_generated) {
                    int index = randomData<int>(0, device_model.ops_size() - 1, rng);
#ifdef STATISTICS
					updateOPCounters("OP_" + std::to_string(index));
					updateOPCounters("TOTAL_OP");
#endif
                    const auto &calleeOrOp = device_model.ops(index);
                    if (calleeOrOp.has_operation()) {
                        DEBUG_PRINT("[GENERATION OP " << calleeOrOp.id() << "]");
                        message = generateMessageFromOp(calleeOrOp.operation(), rng);
                        valid_message_generated = true;
                    }
                }
            } else {
                message = generateMessageRandom(rng, false);
            }
        } else {
            message = generateMessageRandom(rng, false);
        }
    } else {
        message = generateMessageRandom(rng, true);
    }

    DEBUG_PRINT("[GENERATION MESSAGE DONE]");

    return message;
}
