#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    user_file_t* f = (user_file_t*)png_ptr->io_ptr;

    if (length > f->len) {
        png_error(png_ptr, "Read Error");
        return;
    }
    memcpy(data, &f->ptr[f->off], length);
    f->len -= length;
    f->off += length;
}

int LLVMFuzzerTestOneInput(uint8_t* buf, size_t len)
{
    png_uint_32 width, height;
    int color_type, bit_depth, interlace;
    png_structp png_ptr;
    png_infop info_ptr;

    total_alloc = 0ULL;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fatal("png_create_read_struct");
    }

    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, (png_infopp)NULL, (png_infopp)NULL);
        fatal("png_create_info_struct()");
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

    png_ptr->flags &= ~PNG_FLAG_CRC_CRITICAL_MASK;
    png_ptr->flags |= PNG_FLAG_CRC_CRITICAL_IGNORE;
    png_ptr->flags &= ~PNG_FLAG_CRC_ANCILLARY_MASK;
    png_ptr->flags |= PNG_FLAG_CRC_ANCILLARY_NOWARN;

    png_set_mem_fn(png_ptr, NULL, png_user_malloc, png_user_free);

    user_file_t f = {
        .ptr = buf,
        .len = len,
        .off = 0UL,
    };

    png_set_read_fn(png_ptr, (void*)&f, png_user_read_data);

    png_read_info(png_ptr, info_ptr);
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, &interlace, NULL, NULL);
    png_read_png(png_ptr, info_ptr, ~(0), NULL);
    png_bytep* row_pointers = png_get_rows(png_ptr, info_ptr);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
}

#ifdef __cplusplus
}
#endif
