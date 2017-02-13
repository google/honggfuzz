#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <libxml.h>
#include <libxml/relaxng.h>
#include <libxml/xmlerror.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(uint8_t* buf, size_t len)
{
    xmlDocPtr p = xmlReadMemory(buf, len, "http://www.google.com", "UTF-8", XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (p) {
        xmlFreeDoc(p);
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
