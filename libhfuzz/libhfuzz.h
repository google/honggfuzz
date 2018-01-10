#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * buf: input fuzzing data
 * len: size of the 'buf' data
 *
 * Return value: should return 0
 */
int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len);

/*
 * argc: ptr to main's argc
 * argv: ptr to main's argv
 *
 * Return value: ignored
 */
int LLVMFuzzerInitialize(int* argc, char*** argv);

/*
 * Data: data to mutate
 * Size: size of the data to mutate
 * MaxSize: maximum size of the destination buffer
 *
 * Return value: size of the mutated buffer
 */
size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

/*
 *
 * An alternative for LLVMFuzzerTestOneInput()
 *
 * buf_ptr: will be set to input fuzzing data
 * len_ptr: will be set to the size of the input fuzzing data
 */
void HF_ITER(const uint8_t** buf_ptr, size_t* len_ptr);
void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);

#if defined(__linux__)

#include <sched.h>

/*
 * Enter Linux namespaces
 *
 * cloneFlags: see 'man unshare'
 */
bool linuxEnterNs(uintptr_t cloneFlags);
/*
 * Bring network interface up
 *
 * ifacename: name of the interface, typically "lo"
 */
bool linuxIfaceUp(const char* ifacename);
/*
 * Mount tmpfs over a mount point
 *
 * dst: mount point for tmfs
 */
bool linuxMountTmpfs(const char* dst);

#endif /* defined(__linux__) */

#ifdef __cplusplus
} /* extern "C" */
#endif
