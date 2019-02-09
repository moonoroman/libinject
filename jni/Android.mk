LOCAL_PATH := $(call my-dir)

# 清除变量
include $(CLEAR_VARS)

# 对log打印日志消息的支持
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

# 编译后生成的模块的名称
LOCAL_MODULE    := inject

# 参与编译的源码文件
LOCAL_SRC_FILES := f:/android/LibInject/jni/inject.c

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

# 编译生成elf可执行文件
include $(BUILD_EXECUTABLE)