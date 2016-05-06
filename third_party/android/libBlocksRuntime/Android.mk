LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libblocksruntime
LOCAL_SRC_FILES := runtime.c data.c
LOCAL_CFLAGS := -I. -std=c11 -Wall -Wextra -Wno-unused-parameter \
                -Wno-unused-function \
                -DHAVE_SYNC_BOOL_COMPARE_AND_SWAP_INT \
                -DHAVE_SYNC_BOOL_COMPARE_AND_SWAP_LONG
include $(BUILD_STATIC_LIBRARY)

