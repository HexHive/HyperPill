#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    size_t size = 0x100000; // 1 MB
    int fd = open("/dev/random", O_RDONLY);
    sleep(10);
    int i = 0;
    void *bloat = -1;
    if (!fork()) {
        mlockall(MCL_CURRENT | MCL_FUTURE);
        while (bloat != NULL) {
            bloat = malloc(size);
            if (bloat == NULL) {
                printf("MMAP FAILED\n");
            } else {
                memset(bloat, 1, size);
                printf("BLOAT %p\n", bloat);
            }
        }
        exit(0);
    } else {
        wait(NULL);
#if defined(__x86_64__)
        uint64_t rax;
        __asm__ __volatile__("mov $0xdeadbeef, %rax\n");
        asm volatile("vmcall");
#elif defined(__aarch64__)
        const char *filename = "/proc/dummy_hvc";
        FILE *fp = fopen(filename, "w");
        if (!fp) {
            perror("fopen");
            return 1;
        }
        if (fprintf(fp, "1\n") < 0) {
            perror("fprintf");
            fclose(fp);
            return 1;
        }
        fclose(fp);
        return 0;
#endif
    }
}
