#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "conveyor.h"
#include <x86intrin.h>
#include <stdio.h>

#ifndef DEBUG                                                                    
#define DEBUG 0
#endif                                                                           
#define debug_printf(fmt, ...)                                                 \
do {                                                                       \
    if (DEBUG){\
        printf("\n====== pos: %ld\n", input_cursor-input);                                 \
        printf(fmt, __VA_ARGS__);                                 \
            fflush(stdout); \
    } \
} while (0)
        /* printf("INPUT: ");\ */
        /* for(int i=0; i< input_len; i ++){\ */
        /*     if(i == input_cursor -input) printf( "[" );\ */
        /*     printf("%02x ", input[i]); \ */
        /* } \ */
        /* printf("\nOUTPUT: ");\ */
        /* for(int i=0; i< *output_len; i ++){\ */
        /*     printf("%02x ", output[i]); \ */
        /* } \ */
        /* printf("\n=====\n");\ */

#define MAXLEN 8192

static const uint8_t *input;
static const uint8_t *input_cursor;
static size_t input_len;

static uint8_t *output;
static uint8_t *output_mutation_mask;
static uint8_t *output_cursor;
static size_t *output_len;
static size_t output_lenn;

static uint8_t *last_token;
static size_t bufsize;


static uint8_t *zeros;

typedef struct __attribute__((packed)){
    uint8_t op;
    uint32_t start;
    uint32_t len;
    uint32_t dma_start;
    uint32_t dma_len;
} op_log_entry;

struct{
    size_t len;
    op_log_entry data[(4096-sizeof(size_t))/(sizeof(op_log_entry))];
} op_log __attribute__ ((aligned (4096)));

int new_op(uint8_t op, uint32_t start, uint32_t end, uint32_t dma_start, uint32_t dma_len) {
    op_log.data[op_log.len].op = op;
    op_log.data[op_log.len].start = start;
    op_log.data[op_log.len].len = end - start;
    op_log.data[op_log.len].dma_start = dma_start;
    op_log.data[op_log.len].dma_len = dma_len;
    op_log.len++;
    return op_log.len;
}

// Ingest a new input
void ic_new_input(const uint8_t* in, size_t len) {
    bufsize = MAXLEN;
    if(!output) {
        output = (uint8_t*)malloc(bufsize);
        output_len = &output_lenn;
        zeros = (uint8_t*)malloc(bufsize);
        output_mutation_mask = (uint8_t*)malloc(bufsize);
    }
    input = in;
    input_cursor = input;
    input_len = len;

    assert(output);
    output_cursor = output;
    *output_len = 0;
    memset(output_mutation_mask, 0, bufsize-*output_len);
    last_token = output;
}

uint8_t *ic_get_cursor(void){
    return output_cursor;
}
size_t ic_get_last_token(void){
    return last_token-output;
}

size_t ic_lookahead(const char* token, size_t token_len) { 
    size_t ret = 0;
    uint8_t *next_token = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    if(!next_token || next_token+token_len >= input+input_len)
        return ret;
    uint8_t *after_next_token = (uint8_t*) memmem(next_token+token_len,
            input + input_len - next_token - token_len,
            token,
            token_len);
    if(!after_next_token)
        return (input+input_len-next_token-token_len);
    return after_next_token - next_token - token_len;
}

static inline uint8_t* append(const void* src, size_t len){
    if(output_cursor + len > output + bufsize)
        return NULL;
    if(!(output_cursor && output_cursor - output + len <= bufsize)){
        debug_printf("append: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort();
    }
    if(DEBUG){
        printf("Appending %lx Bytes: ", len);
        for(int i=0; i<len; i++)
            printf("%02x ", ((uint8_t*)src)[i]);
        printf("\n");
    }
    memcpy(output_cursor, src, len);
    output_cursor += len;
    *output_len = output_cursor - output;
    return output_cursor;
}

void* ic_insert(void* src, size_t len, size_t pos){
    if(!(output_cursor && output_cursor - output + len < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort();
    }
    if(!((output_cursor - output) + len < bufsize) ) {
        debug_printf("ic_insert: %s", "Assert: ((output_cursor - output) + len < bufsize)\n");
        abort();
    }
    if(!(pos < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (pos < bufsize)\n");
        abort();
    }
    memmove(output+pos+len, output+pos, len);
    memcpy(output+pos, src, len);
    output_cursor += len;
    *output_len = output_cursor - output;
    return output_cursor;
}

void* ic_append(const void* src, size_t len){
    if(!(output_cursor && output_cursor - output + len < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        return NULL;
    }
    if(!((output_cursor - output) + len < bufsize) ) {
        debug_printf("ic_insert: %s", "Assert: ((output_cursor - output) + len < bufsize)\n");
        return NULL;
    }
    return append(src, len);
}


static inline const uint8_t* size_ptr(size_t len){
    if (input_cursor + len > input + input_len)
        return NULL;
    input_cursor += len;
    /* printf("size_ptr: %lx\n", input_cursor-input-len); */
    return input_cursor - len;
}

// Return a "cannonical input": one with extraneous bytes removed, and missing
// bytes inserted (where needed).

uint8_t *ic_get_output(size_t *len)
{
    __fuzzer_set_output(output,
            *output_len);
    __fuzzer_set_op_log((void*)&op_log);
    op_log.len = 0;
    *len = *output_len;
    return output;
}

int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max, bool protect) {
    const void *src = size_ptr(sizeof(uint8_t));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(uint8_t));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(uint8_t)))
            return -1;
        return 0;
    }
    return -1;
}
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max, bool protect) {
    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}
int ic_ingest32(uint32_t *result,uint32_t min, uint32_t max, bool protect) {

    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}

int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max, bool protect) {
    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}

int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max) {
    return ic_ingest8(result, min, max, false);
}
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max) {
    return ic_ingest16(result, min, max, false);
}
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max) {
    return ic_ingest32(result, min, max, false);
}
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max) {
    return ic_ingest64(result, min, max, false);
}

uint8_t* ic_ingest_len(size_t len) {
    debug_printf("INGEST LEN: %ld. CURSOR: %ld INPUT_LEN: %lx\n", len, input_cursor-input, input_len);
    uint8_t *result = output_cursor;

    size_t copy;
    if(input_cursor + len > input + input_len) {
        copy = input+input_len - input_cursor; // len from current input_cursor to end
    } else {
        copy = len;
    }
    const void *src = size_ptr(copy);
    if(!append(src, copy)) {
            return NULL;
    }

    size_t remaining_len = len - copy;
    if(copy != len) {
        srand(__rdtsc());
        memset(zeros, 0, remaining_len);
        for(int i=0; i<(rand()%8)*remaining_len/16 && remaining_len; i++) {
            zeros[rand()%remaining_len] = rand()&0xFF;
        }
    }
    if(!append(zeros, remaining_len)) {
            return NULL;
    }
    return result;
}

// Reads len bytes up until the token.
// If there are insufficient bytes before the token, fill with random bytes (biased to 0)
// Use minlen to increase the number of random bytes, or set minlen = -1 to disable
// Set string=1 if the random bytes should only contain ASCII characters, 0 otherwise
uint8_t* ic_ingest_buf(size_t *len, const char* token, size_t token_len, int minlen, int string) {
    debug_printf("INGEST: %ld %d. CURSOR: %ld INPUT_LEN: %lx\n", *len, minlen, input_cursor-input, input_len);
    uint8_t *result = output_cursor;
    uint8_t *token_position;
    size_t maxlen, until_token_len;
    maxlen = *len;
    size_t remaining_len = maxlen;
    size_t filled = 0;

    token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    token_position= NULL;
    /* debug_printf("TOKEN_POSITION: %p\n", token_position - input_cursor); */
    if(token_position && token_position - input_cursor < maxlen) {
        until_token_len = token_position - input_cursor;
    } else if(token_position) {
        until_token_len = maxlen;
    } else if(input+input_len-input_cursor > maxlen) {
        until_token_len = maxlen;
    } else {
        until_token_len = input+input_len-input_cursor;
    }
    
    debug_printf("UNTIL_TOKEN_LEN: %ld\n", until_token_len);
    // First try to read data from the actual buffer (until token)
    const uint8_t* ret = size_ptr(until_token_len);
    if(ret) { 
        if(!append(ret, until_token_len))
            return NULL;
        filled += until_token_len;
        remaining_len -= until_token_len;
    }

    // Next, fill the rest with random data.
    // Increase the total len to minlen if required
    if(minlen != -1 && remaining_len + filled > minlen) {
        if(minlen > filled)
            remaining_len = minlen - filled;
        else 
            remaining_len = 0;
    }
    srand(__rdtsc());
    memset(zeros, 0, remaining_len);

    if(string) { // Fill it with random ascii
        for(int i=0; i<remaining_len && remaining_len; i++){
            zeros[i] = 0x32 + (rand()%(0x7e - 0x32));
        }
        if(remaining_len){
            zeros[remaining_len-1] = '\x00';
        }
    } else {
        for(int i=0; i < rand()%16*remaining_len/16 && remaining_len; i++) {
            zeros[rand()%remaining_len] = rand()&0xFF;
        }
    }

    if(!append(zeros, remaining_len)) {
            return NULL;
    } else {
        filled += remaining_len;
    }
    *len = filled;
    debug_printf("INGEST RESULT: %ld @%p\n", *len, result);
    return result;
}

void *ic_advance_until_token(const char* token, size_t len) {
    uint8_t* token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        if(*output_len){
            last_token = append(token, len);
            if(!last_token)
                return NULL;
        }
        input_cursor = token_position + len;
    } 
    /* else if (input_cursor < input + input_len) { */
    /*     last_token = append(token, len) - len; */
    /*     token_position = (uint8_t*)input_cursor; */
    /* } */
    return token_position;
}

void ic_dump(){
    printf("IC DUMP:\nINPUT:\n");
    for(int i=0; i<input_len; i++){
        printf("\\x%02x",input[i]);
    }
    printf("\nOUTPUT:\n");
    for(int i=0; i<*output_len; i++){
        printf("\\x%02x",output[i]);
    }
    printf("\n");
}

size_t ic_length_until_token(const char* token, size_t len) {
    uint8_t* token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        return token_position-input_cursor;
    }
    return -1;
}

// Erase until the last token 
void ic_erase_backwards_until_token(void) {
    if(last_token) {
        output_cursor = last_token;
        *output_len = output_cursor - output;
    } else {
        output_cursor = output;
        *output_len = 0;
    }
    debug_printf("Erased Backwards. Cursor is now at %lx\n", *output_len);
    memset(output_mutation_mask, 0, bufsize-*output_len);
}

void ic_subtract(size_t l){
    if(output_cursor - output >=l){
        output_cursor -= l;
        *output_len = output_cursor - output;
    }
    debug_printf("Subtracted %lx. Cursor is now at %lx\n", l, *output_len);
}
