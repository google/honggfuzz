#include "honggfuzz.h"
#include "libhfcommon/log.h"
#include "libhfuzz/persistent.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This mode of discover is employed by honggfuzz
 */
__attribute__((visibility("default"))) __attribute__((used)) const char* LIBHFUZZ_module_main =
    _HF_PERSISTENT_SIG;

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
#if !defined(__CYGWIN__)
__attribute__((weak))
#endif /* !defined(__CYGWIN__) */
int main(int argc, char** argv) {
       /* Make sure the LIBHFUZZ_module_main (persistent) signature) is used */
    LOG_D("Current module: %s", LIBHFUZZ_module_main);
    return HonggfuzzMain(argc, argv);
}
