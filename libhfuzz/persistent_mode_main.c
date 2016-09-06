#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void HF_ITER(uint8_t ** buf, size_t * len);

int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len) __attribute__ ((weak));
int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__ ((weak));
int main(int argc, char **argv) __attribute__ ((weak));

int main(int argc, char **argv)
{
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }
    if (LLVMFuzzerTestOneInput == NULL) {
        fprintf(stderr, "LLVMFuzzerTestOneInput not defined in your code\n");
        _exit(1);
    }

    for (;;) {
        size_t len;
        uint8_t *buf;

        HF_ITER(&buf, &len);

        int ret = LLVMFuzzerTestOneInput(buf, len);
        if (ret != 0) {
            fprintf(stderr, "LLVMFuzzerTestOneInput() returned '%d'\n", ret);
            _exit(1);
        }
    }
}
