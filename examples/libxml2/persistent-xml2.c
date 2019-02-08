#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <libxml.h>
#include <libxml/relaxng.h>
#include <libxml/xmlerror.h>
#include <stdlib.h>

#include <libhfuzz/libhfuzz.h>

FILE* null_file = NULL;

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    null_file = fopen("/dev/null", "w");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    xmlDocPtr p = xmlReadMemory((const char*)buf, len, "http://www.google.com", "UTF-8",
        XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (!p) {
        return 0;
    }
    xmlDocFormatDump(null_file, p, 1);
    xmlFreeDoc(p);
    return 0;
}

#ifdef __cplusplus
}
#endif
