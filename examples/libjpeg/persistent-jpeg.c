#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

#include "cderror.h"
#include "jpeglib.h"

struct jpeg_decompress_struct cinfo;
int null_fd = -1;

struct jpegErrorManager {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

struct jpegErrorManager jerr;

void jpegErrorExit(j_common_ptr cinfo) {
    struct jpegErrorManager* myerr = (struct jpegErrorManager*)cinfo->err;
    longjmp(myerr->setjmp_buffer, 1);
}

static const char* const cdjpeg_message_table[] = {
#include "cderror.h"
    NULL};

static uint64_t max_total_pixels = 1000000000ULL; /* 1G */
int LLVMFuzzerInitialize(int* argc, char*** argv) {
    null_fd = open("/dev/null", O_WRONLY);

    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpegErrorExit;

    jerr.pub.addon_message_table = cdjpeg_message_table;
    jerr.pub.first_addon_message = JMSG_FIRSTADDONCODE;
    jerr.pub.last_addon_message = JMSG_LASTADDONCODE;

    jpeg_create_decompress(&cinfo);

    /* If there are any arguments provided, limit width*height to this value */
    if (*argc > 1) {
        max_total_pixels = strtoull((*argv)[1], NULL, 0);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    if (setjmp(jerr.setjmp_buffer)) {
        goto out;
    }

    jpeg_mem_src(&cinfo, buf, len);
    jpeg_read_header(&cinfo, TRUE);

    /* Limit total number of pixels to decode to 50M */
    uint64_t total_pix = (uint64_t)cinfo.output_height * (uint64_t)cinfo.output_width;
    if (total_pix > max_total_pixels) {
        goto out;
    }

    cinfo.mem->max_memory_to_use = (1024ULL * 1024ULL * 1024ULL);
    cinfo.mem->max_alloc_chunk = (1024ULL * 1024ULL * 1024ULL);

    jpeg_start_decompress(&cinfo);

    int row_stride = cinfo.output_width * cinfo.output_components;
    JSAMPARRAY buffer =
        (*cinfo.mem->alloc_sarray)((j_common_ptr)&cinfo, JPOOL_IMAGE, row_stride, 1);
    while (cinfo.output_scanline < cinfo.output_height) {
#if defined(__clang__)
#if __has_feature(memory_sanitizer)
        __msan_poison(buffer[0], row_stride);
#endif /* __has_feature(memory_sanitizer) */
#endif /* defined(__clang__) */
        jpeg_read_scanlines(&cinfo, buffer, 1);
        write(null_fd, buffer[0], row_stride);
    }

out:
    jpeg_abort_decompress(&cinfo);
    return 0;
}

#ifdef __cplusplus
}
#endif
