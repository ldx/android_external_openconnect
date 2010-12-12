ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    android.c \
    auth.c \
    cstp.c \
    dtls.c \
    http.c \
    main.c \
    mainloop.c \
    securid.c \
    ssl.c \
    ssl_ui.c \
    tun.c \
    version.c \
    xml.c

LOCAL_MODULE_TAGS := eng

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH) \
	external/zlib \
    external/icu4c/common \
	external/libxml2/include \
	external/openssl/include \
	frameworks/base/cmds/keystore

LOCAL_SHARED_LIBRARIES := libssl libcrypto libicuuc
LOCAL_STATIC_LIBRARIES := libcutils libxml2

LOCAL_CFLAGS := -DANDROID_CHANGES

LOCAL_MODULE := openconnect

include $(BUILD_EXECUTABLE)

# connect script
include $(CLEAR_VARS)

LOCAL_MODULE:=openconnect-up
LOCAL_MODULE_TAGS:=user
LOCAL_MODULE_CLASS:=EXECUTABLES
LOCAL_SRC_FILES:=openconnect-up

include $(BUILD_PREBUILT)

endif  # TARGET_SIMULATOR != true
