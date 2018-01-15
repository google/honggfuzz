#include <time.h>
#include <string.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfuzz/persistent.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This mode of discover is employed by honggfuzz
 */
__attribute__((visibility("default")))
__attribute__((used))
const char* LIBHFUZZ_module_main = _HF_PERSISTENT_SIG;

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
#if !defined(__CYGWIN__)
__attribute__((weak))
#endif /* !defined(__CYGWIN__) */
int main(int argc, char** argv) {
    return HonggfuzzMain(argc, argv);
}
