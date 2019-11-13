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

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    tjhandle tjh = tjInitDecompress();

    int width, height, jpegSubsamp, jpegColorspace;
    if (tjDecompressHeader3(tjh, buf, len, &width, &height, &jpegSubsamp, &jpegColorspace) < 0) {
        tjDestroy(tjh);
        return 0;
    }
    unsigned char* dstBuf = tjAlloc(tjBufSizeYUV2(width, 4, height, jpegSubsamp));
    if (!dstBuf) {
        tjDestroy(tjh);
        return 0;
    }
    tjDecompressToYUV2(tjh, buf, len, dstBuf, width, 4, height, 0);
    tjFree(dstBuf);
    tjDestroy(tjh);

    return 0;
}

#ifdef __cplusplus
}
#endif
