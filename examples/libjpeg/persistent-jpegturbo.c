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
    unsigned char* dstBuf = tjAlloc(tjBufSizeYUV2(width, 4, height, jpegSubsamp));
    if (!dstBuf) {
        return;
    }
    tjDecompressToYUV2(tjh, buf, len, dstBuf, width, 4, height, TJFLAG_NOREALLOC);
    tjFree(dstBuf);
}

void decompressToRGB(
    tjhandle tjh, unsigned char* buf, size_t len, int width, int height, int jpegSubsamp) {
    int pitch = width * tjPixelSize[TJPF_RGB];

    unsigned char* dstBuf = tjAlloc(pitch * height + 1);
    if (!dstBuf) {
        return;
    }
    tjDecompress2(tjh, buf, len, dstBuf, width, pitch, height, TJPF_RGB, TJFLAG_NOREALLOC);
    tjFree(dstBuf);
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    tjhandle tjh = tjInitDecompress();

    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(tjh, buf, len, &width, &height, &jpegSubsamp, &jpegColorspace) < 0) {
        tjDestroy(tjh);
        return 0;
    }

    decompressToYUV(tjh, (unsigned char*)buf, len, width, height, jpegSubsamp);
    decompressToRGB(tjh, (unsigned char*)buf, len, width, height, jpegSubsamp);

    tjDestroy(tjh);

    return 0;
}

#ifdef __cplusplus
}
#endif
