#include "common.h"

#include <sstream>
#include <iomanip>

device::Device device_model;
device::VirtIODMAInfo virtio_dma_info;
device::DMAInfo dma_info;
std::unordered_map<int, std::vector<int>> bb_operation_ids;

namespace {
	uint8_t state = 0;
}

uint8_t get_state() {
	return state;
}

void set_state(uint8_t new_state) {
	state = new_state;
}

bool isDeviceInitialized() {
    return device_model.ByteSizeLong() > 0;
}

bool isVirtIODMAInitialized() {
	return virtio_dma_info.ByteSizeLong() > 0 && !getenv("DISABLE_STATE");
}

bool isDMAInitialized() {
	return dma_info.ByteSizeLong() > 0;
}

virtfuzz::DataSize getRandomDataSize(std::mt19937& rng, bool is_pio) {
    if (is_pio) {
        std::uniform_int_distribution<int> dist(1, 3);
        switch (dist(rng)) {
            case 1: return virtfuzz::BYTE;
            case 2: return virtfuzz::WORD;
            case 3: return virtfuzz::LONG;
            default: return virtfuzz::SIZE_UNSPECIFIED; // Default case, should not happen
        }
    } else {
        std::uniform_int_distribution<int> dist(1, 4);
        switch (dist(rng)) {
            case 1: return virtfuzz::BYTE;
            case 2: return virtfuzz::WORD;
            case 3: return virtfuzz::LONG;
            case 4: return virtfuzz::QUAD;
            default: return virtfuzz::SIZE_UNSPECIFIED; // Default case, should not happen
        }
    }
}

std::string messageToReadableString(const virtfuzz::Message& message) {
    std::ostringstream oss;

    switch (message.type()) {
        case virtfuzz::MMIO_READ: {
            const auto& mmio_read = message.mmio_read_message();
            oss << "MMIO_READ: region_id=" << mmio_read.region_id()
                << ", addr=0x" << std::hex << mmio_read.addr()
                << ", size=0x" << mmio_read.size();
            break;
        }
        case virtfuzz::MMIO_WRITE: {
            const auto& mmio_write = message.mmio_write_message();
            oss << "MMIO_WRITE: region_id=" << mmio_write.region_id()
                << ", addr=0x" << std::hex << mmio_write.addr()
                << ", size=0x" << mmio_write.size()
                << ", value=0x" << mmio_write.value();
            break;
        }
        case virtfuzz::PIO_READ: {
            const auto& pio_read = message.pio_read_message();
            oss << "PIO_READ: port=0x" << std::hex << pio_read.port()
                << ", size=0x" << pio_read.size();
            break;
        }
        case virtfuzz::PIO_WRITE: {
            const auto& pio_write = message.pio_write_message();
            oss << "PIO_WRITE: port=0x" << std::hex << pio_write.port()
                << ", size=0x" << pio_write.size()
                << ", value=0x" << pio_write.value();
            break;
        }
		case virtfuzz::DMA: {
			const auto& dma_message = message.dma_message();

			oss << "DMA Message Type: ";
			if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
				oss << "Normal";
			} else if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_STRUCTURE) {
				oss << "Structure";
			} else {
				oss << "Virtio";
			}
			oss << std::endl;
			
			if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_VIRTIO) {
				const auto& virtio_message = dma_message.dma_virtio_message();
				oss << "Queue Number: " << virtio_message.queue_num() << std::endl;

				for (const auto& vmsg : virtio_message.virtio_message()) {
					oss << "VirtIO Direction: " << (vmsg.virtio_direction() == virtfuzz::VIRTIO_OUT ? "Out" : "In") << std::endl;

					if (vmsg.virtio_direction() == virtfuzz::VIRTIO_OUT) {
						const auto& out_message = vmsg.virtio_out_message();
						oss << "Out Message Len: " << out_message.len() << std::endl;
						oss << "Out Message Data: [";
						for (int i = 0; i < out_message.data().size(); ++i) {
							if (i > 0) {
								oss << ", ";
							}
							oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(static_cast<uint8_t>(out_message.data()[i])) & 0xFF);
						}
						oss << "]";
					} else if (vmsg.virtio_direction() == virtfuzz::VIRTIO_IN) {
						const auto& in_message = vmsg.virtio_in_message();
						oss << "In Message Len: " << in_message.len();
					}
				}
			} else if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_NORMAL) {
				const auto& random_message = dma_message.dma_random_message();
				oss << "Index: 0x" << std::hex << random_message.index() << std::endl;
				oss << "Stride: 0x" << std::hex << random_message.stride() << std::endl;
				oss << "Len: 0x" << std::hex << random_message.len() << std::endl;
				oss << "Data: [";
				for (int i = 0; i < random_message.data().size(); ++i) {
					if (i > 0) {
						oss << ", ";
					}
					oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(static_cast<uint8_t>(random_message.data()[i])) & 0xFF);
				}
				oss << "]";
			} else if (dma_message.dma_message_type() == virtfuzz::DMA_MESSAGE_STRUCTURE) {
				const auto& random_message = dma_message.dma_random_message();
				oss << "Index: 0x" << std::hex << random_message.index() << std::endl;
				oss << "Len: 0x" << std::hex << random_message.len() << std::endl;
				oss << "Data: [";
				for (int i = 0; i < random_message.data().size(); ++i) {
					if (i > 0) {
						oss << ", ";
					}
					oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(static_cast<uint8_t>(random_message.data()[i])) & 0xFF);
				}
				oss << "]";
			}

			break;
		}
        default:
            oss << "UNKNOWN MESSAGE TYPE";
            break;
    }

    return oss.str();
}

std::string messageSequenceToReadableString(const virtfuzz::MessageSequence& message_sequence) {
    std::ostringstream oss;
    for (int i = 0; i < message_sequence.messages_size(); ++i) {
        const auto& message = message_sequence.messages(i);
        oss << "[MESSAGE " << (i + 1) << "]: " << messageToReadableString(message) << std::endl;
    }
    return oss.str();
}

