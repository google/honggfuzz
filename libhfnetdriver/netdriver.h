/*
 *
 * honggfuzz - network driver for fuzzing
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_NETDRIVER_NETDRIVER_H
#define _HF_NETDRIVER_NETDRIVER_H

#include <inttypes.h>
#include <stdint.h>

/*
 * Flags which will be passed to the original program running in a separate thread should go into
 * server_argc/server_argv
 */
int HonggfuzzNetDriverArgsForServer(int argc, char **argv, int *server_argc, char ***server_argv);
/*
 * TCP port that the fuzzed data inputs will be sent to
 */
uint16_t HonggfuzzNetDriverPort(int argc, char **argv);

#endif /* ifndef _HF_NETDRIVER_NETDRIVER_H_ */
