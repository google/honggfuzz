#   honggfuzz - Android makefile
#   -----------------------------------------
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

LOCAL_PATH := $(abspath $(call my-dir)/..)
include $(CLEAR_VARS)

LOCAL_MODULE := honggfuzz
LOCAL_SRC_FILES := honggfuzz.c log.c files.c fuzz.c report.c mangle.c util.c
LOCAL_CFLAGS := -std=c11 -I. \
    -D_GNU_SOURCE \
    -Wall -Wextra -Wno-initializer-overrides -Wno-override-init -Wno-unknown-warning-option -Werror \
    -funroll-loops -O2
LOCAL_LDFLAGS := -lm

ARCH_SRCS := $(wildcard posix/*.c)
ARCH = POSIX

LOCAL_SRC_FILES += $(ARCH_SRCS)
LOCAL_CFLAGS += -D_HF_ARCH_${ARCH}

include $(BUILD_EXECUTABLE)
