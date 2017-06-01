#ifdef __cplusplus
extern "C" {
#endif

/*
 * buf: input fuzzing data
 * len: size of the 'buf' data
 *
 * Return value: should return 0
 */
    int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len);

/*
 * argc: ptr to main's argc
 * argv: ptr to main's argv
 *
 * Return value: ignored
 */
    int LLVMFuzzerInitialize(int *argc, char ***argv);

/*
 *
 * An alternative for LLVMFuzzerTestOneInput()
 *
 * buf_ptr: will be set to input fuzzing data
 * len_ptr: will be set to the size of the input fuzzing data
 */
    void HF_ITER(uint8_t ** buf_ptr, size_t * len_ptr);

#ifdef __cplusplus
}                               /* extern "C" */
#endif
