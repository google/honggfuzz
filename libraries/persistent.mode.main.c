#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void HF_ITER(uint8_t ** buf, size_t * len);

int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len);
__attribute__ ((weak))
int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) __attribute__ ((weak));

int main(int argc, char **argv)
{
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }

    for (;;) {
        size_t len;
        uint8_t *buf;

        HF_ITER(&buf, &len);

        int ret = LLVMFuzzerTestOneInput(buf, len);
        if (ret != 0) {
            printf("LLVMFuzzerTestOneInput() returned '%d'", ret);
            _exit(1);
        }
    }
}
