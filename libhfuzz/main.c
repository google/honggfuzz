#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfuzz/persistent.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This mode of discover is employed by honggfuzz
 */
__attribute__((used)) const char* LIBHFUZZ_module_main = _HF_PERSISTENT_SIG;

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
#if !defined(__CYGWIN__)
__attribute__((weak))
#endif /* !defined(__CYGWIN__) */
int main(int argc, char** argv) {
    /*
     * getpid() never returns -2, so it's only to reference the persistent
     * signature, to prevent optimizing it out by clever compiler/link
     * optimizers
     */
    if (getpid() == -2) {
      return (int)strlen(LIBHFUZZ_module_main);
    }
    return HonggfuzzMain(argc, argv);
}
