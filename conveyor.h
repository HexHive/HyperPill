#ifndef CONVEYOR_H
#define CONVEYOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define SEPARATOR "FUZZ"
#define SEPARATOR_LEN 4

void ic_setup(size_t max_input);
void ic_new_input(const uint8_t* in, size_t len);
uint8_t *ic_get_output(size_t *len);
int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max, bool protect);
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max, bool protect);
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max, bool protect);
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max, bool protect);
int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max);
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max);
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max);
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max);
uint8_t* ic_ingest_len(size_t len);
uint8_t* ic_ingest_buf(size_t *len, const char* token, size_t token_len, int minlen, int string);
void *ic_advance_until_token(const char* token, size_t len);
size_t ic_get_last_token(void);
void* ic_insert(void* src, size_t len, size_t pos);
void* ic_append(const void* src, size_t len);
size_t ic_length_until_token(const char* token, size_t len);
void ic_erase_backwards_until_token(void);
uint8_t *ic_get_cursor(void);
void ic_dump();

// Returns the size of the next buffer
size_t ic_lookahead(const char* token, size_t token_len) ;
void ic_subtract(size_t l);

int new_op(uint8_t op, uint32_t start, uint32_t end, uint32_t dma_start, uint32_t dma_len);

extern "C" {
void __fuzzer_set_output(uint8_t *data, size_t size);
void __fuzzer_set_op_log(void *log);
}

#endif
