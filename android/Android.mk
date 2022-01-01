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

APP_UNIFIED_HEADERS := true
LOCAL_PATH := $(abspath $(call my-dir)/..)

# Maintain a local copy since some NDK versions lose LOCAL_PATH scope at POST_BUILD_EVENT
MY_LOCAL_PATH := $(LOCAL_PATH)

# Force a clean if target API has changed and a previous build exists
CLEAN_RUN := false
ifneq ("$(wildcard $(LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/android_api.txt)","")
  CACHED_API := $(shell cat "$(LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/android_api.txt")
  ifneq ($(APP_PLATFORM),$(CACHED_API))
    $(info [!] Previous build was targeting different API level - cleaning)
    CLEAN_RUN := $(shell make clean &>/dev/null && echo true || echo false)
  endif
endif

# Force a clean if selected toolchain has changed and a previous build exists
ifeq ($(CLEAN_RUN),false)
  ifneq ("$(wildcard $(LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/ndk_toolchain.txt)","")
    CACHED_TOOLCHAIN := $(shell cat "$(LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/ndk_toolchain.txt")
    ifneq ($(NDK_TOOLCHAIN),$(CACHED_TOOLCHAIN))
      $(info [!] Previous build was using different toolchain - cleaning)
      CLEAN_RUN := $(shell make clean &>/dev/null && echo true || echo false)
    endif
  endif
endif

ifeq ($(APP_ABI),$(filter $(APP_ABI),armeabi armeabi-v7a))
  ARCH_ABI := arm
else ifeq ($(APP_ABI),$(filter $(APP_ABI),x86))
  ARCH_ABI := x86
else ifeq ($(APP_ABI),$(filter $(APP_ABI),arm64-v8a))
  ARCH_ABI := aarch64
else ifeq ($(APP_ABI),$(filter $(APP_ABI),x86_64))
  ARCH_ABI := x86_64
else
  $(error Unsuported / Unknown APP_API '$(APP_ABI)')
endif

# Enable Linux ptrace() instead of POSIX signal interface by default
ANDROID_WITH_PTRACE ?= true

ifeq ($(ANDROID_WITH_PTRACE),true)
  # Additional libcrypto OpenSSL flags required to mitigate bug (ARM systems with API <= 21)
  ifeq ($(APP_ABI),$(filter $(APP_ABI),armeabi))
    OPENSSL_ARMCAP_ABI := "5"
  else ifeq ($(APP_ABI),$(filter $(APP_ABI),armeabi-v7a))
    OPENSSL_ARMCAP_ABI := "7"
  endif

  # Upstream libunwind compiled from sources with Android NDK toolchain
  LIBUNWIND_A := third_party/android/libunwind/src/.libs/libunwind-$(ARCH_ABI).a
  ifeq ("$(wildcard $(LIBUNWIND_A))","")
    $(error libunwind-$(ARCH_ABI) is missing - to build execute \
            'third_party/android/scripts/compile-libunwind.sh third_party/android/libunwind $(ARCH_ABI)')
  endif

  include $(CLEAR_VARS)
  LOCAL_MODULE := libunwind
  LOCAL_SRC_FILES := third_party/android/libunwind/src/.libs/libunwind.a
  LOCAL_EXPORT_C_INCLUDES := third_party/android/libunwind/include
  include $(PREBUILT_STATIC_LIBRARY)

  include $(CLEAR_VARS)
  LOCAL_MODULE := libunwind-arch
  LOCAL_SRC_FILES := third_party/android/libunwind/src/.libs/libunwind-$(ARCH_ABI).a
  LOCAL_EXPORT_C_INCLUDES := third_party/android/libunwind/include
  include $(PREBUILT_STATIC_LIBRARY)

  include $(CLEAR_VARS)
  LOCAL_MODULE := libunwind-ptrace
  LOCAL_SRC_FILES := third_party/android/libunwind/src/.libs/libunwind-ptrace.a
  LOCAL_EXPORT_C_INCLUDES := third_party/android/libunwind/include
  include $(PREBUILT_STATIC_LIBRARY)

  LOCAL_MODULE := libunwind-dwarf-generic
  LOCAL_SRC_FILES := third_party/android/libunwind/src/.libs/libunwind-dwarf-generic.a
  LOCAL_EXPORT_C_INCLUDES := third_party/android/libunwind/include
  include $(PREBUILT_STATIC_LIBRARY)

  # Upstream capstone compiled from sources with Android NDK toolchain
  LIBCAPSTONE_A := third_party/android/capstone/libcapstone.a
  ifeq ("$(wildcard $(LIBCAPSTONE_A))","")
    $(error libcapstone is missing - to build execute \
            'third_party/android/scripts/compile-capstone.sh third_party/android/capstone $(ARCH_ABI)')
  endif
  include $(CLEAR_VARS)
  LOCAL_MODULE := libcapstone
  LOCAL_SRC_FILES := $(LIBCAPSTONE_A)
  LOCAL_EXPORT_C_INCLUDES := third_party/android/capstone/include
  include $(PREBUILT_STATIC_LIBRARY)
endif

ifneq (,$(findstring clang,$(NDK_TOOLCHAIN)))
  LIBBRT_A := third_party/android/libBlocksRuntime/obj/local/$(APP_ABI)/libblocksruntime.a
  ifeq ("$(wildcard $(LIBBRT_A))","")
    $(error libBlocksRuntime is missing - to build execute \
            'third_party/android/scripts/compile-libBlocksRuntime.sh third_party/android/libBlocksRuntime $(ARCH_ABI)')
  endif
  include $(CLEAR_VARS)
  LOCAL_MODULE := libblocksruntime
  LOCAL_SRC_FILES := $(LIBBRT_A)
  include $(PREBUILT_STATIC_LIBRARY)
endif

ifeq ($(ANDROID_WITH_PTRACE),true)
  ARCH_SRCS := linux/arch.c linux/trace.c linux/perf.c linux/unwind.c linux/pt.c
  ARCH := LINUX
  $(info $(shell (echo "********************************************************************")))
  $(info $(shell (echo "Android PTRACE build: Will prevent debuggerd from processing crashes")))
  $(info $(shell (echo "********************************************************************")))
else
  ARCH_SRCS := posix/arch.c
  ARCH := POSIX
  $(info $(shell (echo "********************************************************************")))
  $(info $(shell (echo "Android POSIX build: Will allow debuggerd to also process crashes")))
  $(info $(shell (echo "********************************************************************")))
endif

COMMON_CFLAGS := -std=c11 \
  -D_GNU_SOURCE \
  -Wall -Wextra -Wno-initializer-overrides -Wno-override-init \
  -Wno-atomic-alignment -Wno-unknown-warning-option \
  -Werror -funroll-loops -O2 \
  -Wno-format-truncation \

ifneq (,$(findstring clang,$(NDK_TOOLCHAIN)))
  COMMON_CFLAGS += -fblocks -fno-sanitize=address,undefined,memory,thread -fsanitize-coverage=0
  COMMON_STATIC_LIBS += libblocksruntime
endif

# libhfcommon module
include $(CLEAR_VARS)
LOCAL_MODULE := hfcommon
LOCAL_SRC_FILES := $(wildcard libhfcommon/*.c)
LOCAL_CFLAGS := -D_HF_ARCH_${ARCH} $(COMMON_CFLAGS)
LOCAL_STATIC_LIBRARIES := $(COMMON_STATIC_LIBS)
include $(BUILD_STATIC_LIBRARY)

# libhfuzz module
include $(CLEAR_VARS)
LOCAL_MODULE := hfuzz
LOCAL_SRC_FILES := $(wildcard libhfuzz/*.c)
LOCAL_CFLAGS := -D_HF_ARCH_${ARCH} $(COMMON_CFLAGS) \
  -fPIC -fno-builtin -fno-stack-protector
LOCAL_STATIC_LIBRARIES := $(COMMON_STATIC_LIBS)
include $(BUILD_STATIC_LIBRARY)

# libhfnetdriver module
include $(CLEAR_VARS)
LOCAL_MODULE := hfnetdriver
LOCAL_SRC_FILES := $(wildcard libhfnetdriver/*.c)
LOCAL_CFLAGS := -D_HF_ARCH_${ARCH} $(COMMON_CFLAGS) \
  -fPIC -fno-builtin
LOCAL_STATIC_LIBRARIES := $(COMMON_STATIC_LIBS)
include $(BUILD_STATIC_LIBRARY)

# Main honggfuzz module
include $(CLEAR_VARS)
LOCAL_MODULE := honggfuzz
LOCAL_SRC_FILES := $(wildcard *.c)
LOCAL_CFLAGS := $(COMMON_CFLAGS)
LOCAL_LDFLAGS := -lm -latomic -lz
LOCAL_STATIC_LIBRARIES := $(COMMON_STATIC_LIBS) hfcommon

ifeq ($(ANDROID_WITH_PTRACE),true)
  LOCAL_STATIC_LIBRARIES += libunwind-arch \
    libunwind \
    libunwind-ptrace \
    libunwind-dwarf-generic \
    libcapstone
  LOCAL_CFLAGS += -D__HF_USE_CAPSTONE__
  ifeq ($(ARCH_ABI),arm)
    LOCAL_CFLAGS += -DOPENSSL_ARMCAP_ABI='$(OPENSSL_ARMCAP_ABI)'
  endif
endif

LOCAL_SRC_FILES += $(ARCH_SRCS)
LOCAL_CFLAGS += -D_HF_ARCH_${ARCH}

include $(BUILD_EXECUTABLE)

# The NDK build system does not copy static libraries into project/packages
# so it has to be done manually in order to have all output under a single path.
# Also save some build attribute cache files so that cleans can be enforced when
# required.
all:POST_BUILD_EVENT
POST_BUILD_EVENT:
	@echo $(APP_PLATFORM) > $(MY_LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/android_api.txt
	@echo $(NDK_TOOLCHAIN) > $(MY_LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/ndk_toolchain.txt
	@test -f $(MY_LOCAL_PATH)/obj/local/$(TARGET_ARCH_ABI)/libhfuzz.a && \
    cp $(MY_LOCAL_PATH)/obj/local/$(TARGET_ARCH_ABI)/libhfuzz.a \
    $(MY_LOCAL_PATH)/libs/$(TARGET_ARCH_ABI)/libhfuzz.a || true
