#ifndef VIRTFUZZ_H
#define VIRTFUZZ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MMIO_READ = 0,
    MMIO_WRITE = 1,
    PIO_READ = 2,
    PIO_WRITE = 3,
    DMA = 4,
} MessageType;

typedef enum {
    SIZE_UNSPECIFIED = 0,
    BYTE = 1,
    WORD = 2,
    LONG = 4,
    QUAD = 8
} DataSize;

typedef struct {
    uint8_t region_id;
    uint32_t addr;
    DataSize size;
} MMIOReadMessage;

typedef struct {
    uint8_t region_id;
    uint32_t addr;
    DataSize size;
    uint64_t value;
} MMIOWriteMessage;

typedef struct {
    uint8_t region_id;
    uint32_t port;
    DataSize size;
} PIOReadMessage;

typedef struct {
    uint8_t region_id;
    uint32_t port;
    DataSize size;
    uint32_t value;
} PIOWriteMessage;

typedef enum {
    VIRTIO_DIRECTION_IN = 0,
    VIRTIO_DIRECTION_OUT = 1
} VirtIODirection;

typedef struct {
    uint32_t len;
    uint8_t* data;
} VirtIOOutMessage;

typedef struct {
    uint32_t len;
} VirtIOInMessage;

typedef struct {
    VirtIODirection virtio_direction;
    union {
        VirtIOOutMessage virtio_out_message;
        VirtIOInMessage virtio_in_message;
    } virtio_message;
} VirtIOMessage;

typedef struct {
	uint32_t size;
    uint32_t queue_num;
    VirtIOMessage* virtio_messages;
} DMAVirtioMessage;

typedef struct {
    uint8_t index;
    uint8_t stride;
    uint16_t len;
    uint8_t* data;
} DMARandomMessage;

typedef enum {
    DMA_MESSAGE_TYPE_NORMAL,
    DMA_MESSAGE_TYPE_VIRTIO,
    DMA_MESSAGE_TYPE_STRUCTURE,
} DMAMessageType;

typedef struct {
    DMAMessageType dma_message_type;
    union {
        DMARandomMessage dma_random_message;
        DMAVirtioMessage dma_virtio_message;
    } dma_message_content;
} DMAMessage;

typedef struct {
    MessageType type;
    union {
        MMIOReadMessage mmio_read_message;
        MMIOWriteMessage mmio_write_message;
        PIOReadMessage pio_read_message;
        PIOWriteMessage pio_write_message;
        DMAMessage dma_message;
    } message_content;
} Message;

typedef struct {
    Message *messages;  // Pointer to an array of messages
    size_t message_count;  // Number of messages in the array
} MessageSequence;

typedef enum {
    INTERFACE_TYPE_MMIO,
    INTERFACE_TYPE_PIO,
	INTERFACE_TYPE_DMA,
    INTERFACE_TYPE_NUM,
} InterfaceType;

typedef struct {
    InterfaceType type;
    char name[32];
    uint64_t addr;
    uint32_t size;
    uint8_t min_access_size;
    uint8_t max_access_size;
} InterfaceDescription;

int init_device_model(const char *file_path);

// Function to get the entire message sequence
size_t get_message_sequence(const uint8_t *data, size_t size, MessageSequence *message_sequence);
size_t cleanup(MessageSequence *message_sequence);

size_t virtfuzzCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);
size_t virtfuzzCustomCrossOver(const uint8_t *data1, size_t size1,
		const uint8_t *data2, size_t size2, uint8_t *out, size_t max_out_size, unsigned int seed);

int get_number_of_interfaces(void);
void add_interface(InterfaceType type, uint64_t addr, uint32_t size,
        const char *name, uint8_t min_access_size, uint8_t max_access_size);
void print_interfaces(void);

#ifdef __cplusplus
}
#endif

#endif // VIRTFUZZ_H
