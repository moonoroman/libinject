/* 
 * log.h 
 * 
 *  Created on: 2016-12-26 
 *      Author: fly2016 
 */  
  
#ifndef LOG_H_  
#define LOG_H_  
  
#include <android/log.h>  // 使用log打印日志  
  
  
#define LOG_TAG "INJECT"    // adb logcat -s INJECT  
  
// 设置当前模式为调试模式  
#define DEBUG   1  
  
#ifdef DEBUG  
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)  
#define LOGE(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)  
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)  
#else  
#define LOGI(fmt, args...) while(0)  
#define LOGE(fmt, args...) while(0)  
#define LOGD(fmt, args...)  while(0)  
#endif  
  
#endif /* LOG_H_ */  