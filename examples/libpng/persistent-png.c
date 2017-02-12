#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "png.h"
#include "pngpriv.h"
#include "pngstruct.h"

void fatal(const char* s, ...)
{
    va_list args;
    va_start(args, s);
    vfprintf(stderr, s, args);
    fprintf(stderr, "\n");
    va_end(args);
    _exit(EXIT_FAILURE);
}

typedef struct {
    uint8_t* ptr;
    size_t len;
    size_t off;
} user_file_t;

size_t total_alloc = 0ULL;
int null_fd = -1;

png_voidp png_user_malloc(png_structp png_ptr, png_alloc_size_t sz)
{
    if (sz > (1024ULL * 1024ULL * 64ULL)) {
        return NULL;
    }
    if ((total_alloc + sz) > (1024ULL * 1024ULL * 256ULL)) {
        return NULL;
    }
    total_alloc += sz;

    return malloc(sz);
}

void png_user_free(png_structp png_ptr, png_voidp ptr)
{
    free(ptr);
}

void png_user_read_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
#if defined(__clang__)
#if __has_feature(memory_sanitizer)
            __msan_poison(data, length);
#endif /* __has_feature(memory_sanitizer) */
#endif /* defined(__clang__) */

    user_file_t* f = (user_file_t*)png_ptr->io_ptr;

    if (length > f->len) {
        png_error(png_ptr, "Read Error");
        return;
    }
    memcpy(data, &f->ptr[f->off], length);
    f->len -= length;
    f->off += length;
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    null_fd = open("/dev/null", O_WRONLY);
    return 0;
}

int LLVMFuzzerTestOneInput(uint8_t* buf, size_t len)
{
    png_uint_32 width, height;
    int color_type, bit_depth, interlace, compression_type, filter_type;
    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;

    total_alloc = 0ULL;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fatal("png_create_read_struct");
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    user_file_t f = {
        .ptr = buf,
        .len = len,
        .off = 0UL,
    };
    png_set_read_fn(png_ptr, (void*)&f, png_user_read_data);

    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, (png_infopp)NULL, (png_infopp)NULL);
        fatal("png_create_info_struct()");
    }

    png_set_keep_unknown_chunks(png_ptr, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);

    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
    png_ptr->flags &= ~PNG_FLAG_CRC_CRITICAL_MASK;
    png_ptr->flags |= PNG_FLAG_CRC_CRITICAL_IGNORE;
    png_ptr->flags &= ~PNG_FLAG_CRC_ANCILLARY_MASK;
    png_ptr->flags |= PNG_FLAG_CRC_ANCILLARY_NOWARN;

    png_set_mem_fn(png_ptr, NULL, png_user_malloc, png_user_free);

    png_read_info(png_ptr, info_ptr);
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, &interlace, &compression_type, &filter_type);
    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);

    png_bytep regular_row = png_user_malloc(png_ptr, rowbytes);
    if (!regular_row) {
        fatal("Error allocating memory (row)");
    }
    png_bytep display_row = png_user_malloc(png_ptr, rowbytes);
    if (!display_row) {
        fatal("Error allocating memory (display_row)");
    }

    int passes = png_get_interlace_type(png_ptr, info_ptr) == PNG_INTERLACE_ADAM7 ? 7 : 1;

    png_start_read_image(png_ptr);
    for (int pass = 0; pass < passes; ++pass) {
        for (png_uint_32 h = 0; h < height; h++) {
#if defined(__clang__)
#if __has_feature(memory_sanitizer)
            __msan_poison(regular_row, rowbytes);
            __msan_poison(display_row, rowbytes);
#endif /* __has_feature(memory_sanitizer) */
#endif /* defined(__clang__) */

            png_read_row(png_ptr, regular_row, display_row);

            write(null_fd, regular_row, rowbytes);
            write(null_fd, display_row, rowbytes);
        }
    }
    png_read_end(png_ptr, info_ptr);

    free(regular_row);
    free(display_row);

    return 0;
}

#ifdef __cplusplus
}
#endif
