#include "persistent.mode.func.c"

#ifdef __cplusplus
extern "C" {
#endif

    int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len);
    __attribute__ ((weak))
    int LLVMFuzzerInitialize(int *argc, char ***argv);

    int main(int argc, char **argv) {
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

#ifdef __cplusplus
}
#endif
