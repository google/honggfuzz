#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

#include "turbojpeg.h"

void decompressToYUV(
    tjhandle tjh, unsigned char* buf, size_t len, int width, int height, int jpegSubsamp) {
    unsigned char* dstBuf = malloc(tjBufSizeYUV2(width, 4, height, jpegSubsamp));
    if (!dstBuf) {
        return;
    }
    tjDecompressToYUV2(tjh, buf, len, dstBuf, width, 4, height, 0);
    free(dstBuf);
}

void decompressToRGB(
    tjhandle tjh, unsigned char* buf, size_t len, int width, int height, int jpegSubsamp) {
    size_t dstBufSz = (size_t)width * tjPixelSize[TJPF_RGB] * height;
    unsigned char* dstBuf = malloc(dstBufSz);
    if (!dstBuf) {
        return;
    }
    tjDecompress2(tjh, buf, len, dstBuf, width, 0, height, TJPF_RGB, 0);
    free(dstBuf);
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    tjhandle tjh = tjInitDecompress();

    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(tjh, buf, len, &width, &height, &jpegSubsamp, &jpegColorspace) < 0) {
        tjDestroy(tjh);
        return 0;
    }

    if (((uint64_t)width * (uint64_t)height) <= (1024ULL * 1024ULL)) {
        decompressToRGB(tjh, (unsigned char*)buf, len, width, height, jpegSubsamp);
        decompressToYUV(tjh, (unsigned char*)buf, len, width, height, jpegSubsamp);
    }

    tjDestroy(tjh);

    return 0;
}

#ifdef __cplusplus
}
#endif
