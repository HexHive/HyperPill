#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#define VMCALL_ID 0xdeadbeef
int main() {
    size_t size = 0x100000; // 4G
    int fd = open("/dev/random", O_RDONLY);
    sleep(10);
    int i =0;
    void *bloat = -1;
    if(!fork()) {
        mlockall( MCL_CURRENT | MCL_FUTURE );

            while(bloat !=  NULL){
                    bloat = malloc(size);
                    if(bloat == NULL) {
                            printf("MMAP FAILED\n");
                    } else {
                            memset(bloat, 1, size);
                            printf("BLOAT %p\n", bloat);
                    }
            }
    exit(0);
    } else {
            wait(NULL);
            uint64_t rax = VMCALL_ID;
            __asm__ __volatile__("mov $0xdeadbeef, %rax\n");
            asm volatile("vmcall");
    }
}

