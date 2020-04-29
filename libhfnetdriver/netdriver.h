#ifndef _HF_NETDRIVER_NETDRIVER_H
#define _HF_NETDRIVER_NETDRIVER_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HFND_TMP_DIR_OLD       "/tmp/FUZZ"
#define HFND_TMP_DIR           "/tmp/HFND_TMP_DIR"
#define HFND_DEFAULT_TCP_PORT  8080
#define HFND_DEFAULT_SOCK_PATH "socket"

/*
 * Flags which will be passed to the original program running in a separate thread should go into
 * server_argc/server_argv
 */
int HonggfuzzNetDriverArgsForServer(int argc, char** argv, int* server_argc, char*** server_argv);
/*
 * TCP port that the fuzzed data inputs will be sent to
 */
uint16_t HonggfuzzNetDriverPort(int argc, char** argv);
/*
 * Mount point for temporary filesystem
 */
int HonggfuzzNetDriverTempdir(char* str, size_t size);
/*
 * Provide your own connection address, could be e.g. an AF_UNIX socket.
 *
 * Return 0 if only the standard connection protocols should be used (i.e. currently TCP4/TCP6 and
 * PF_UNIX via a set of standardized TCP ports (e.g. 8080) and paths)
 */
socklen_t HonggfuzzNetDriverServerAddress(struct sockaddr_storage* addr, int* type, int* protocol);

#ifdef __cplusplus
}
#endif

#endif /* ifndef _HF_NETDRIVER_NETDRIVER_H_ */
