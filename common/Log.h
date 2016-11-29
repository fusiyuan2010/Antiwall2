/*
此模块不是一个类（历史原因），而是全局函数和宏
可以动态载入配置项
线程安全

by fusiyuan2010@gmail.com
*/
#ifndef _LOG_H
#define _LOG_H

enum LOG_LEVEL
{
		LTRACE,
		LDEBUG,
		LINFO,
        LWARN,
		LERROR,
        LDUMP,
};


int LogInit(const char *log_file, int level);
int LogMsg(int curlevel,const char *sourceName,int sourceLine,const char *functionName,const char *szFormat, ...);
int LogDestroy();


#ifdef _LOG_NONE
#define LOG_TRACE(format,...)
#define LOG_WARN(format,...)
#define LOG_DEBUG(format,...)
#define LOG_WARN(format,...)
#define LOG_INFO(format,...)
#define LOG_ERROR(format,...)
#define LOG_DUMP(format,...)
#endif

#ifdef _LOG_DEBUG
#define LOG_TRACE(format,...)
#define LOG_DEBUG(format,...) LogMsg(LDEBUG,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_INFO(format,...) LogMsg(LINFO,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_WARN(format,...) LogMsg(LWARN,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_ERROR(format,...) LogMsg(LERROR,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif

#ifdef _LOG_INFO
#define LOG_TRACE(format,...)
#define LOG_DEBUG(format,...)
#define LOG_INFO(format,...) LogMsg(LINFO,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_WARN(format,...) LogMsg(LWARN,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_ERROR(format,...) LogMsg(LERROR,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif

#ifdef _LOG_WARN
#define LOG_TRACE(format,...)
#define LOG_DEBUG(format,...)
#define LOG_INFO(format,...)
#define LOG_WARN(format,...) LogMsg(LWARN,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_ERROR(format,...) LogMsg(LERROR,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif
#ifdef _LOG_ERROR
#define LOG_TRACE(format,...)
#define LOG_DEBUG(format,...)
#define LOG_INFO(format,...)
#define LOG_WARN(format,...)
#define LOG_ERROR(format,...) LogMsg(LERROR,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif

#ifdef _LOG_DUMP
#define LOG_TRACE(format,...)
#define LOG_DEBUG(format,...)
#define LOG_INFO(format,...)
#define LOG_WARN(format,...)
#define LOG_ERROR(format,...)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif 

#ifdef _LOG_TRACE
#define LOG_TRACE(format,...) LogMsg(LTRACE,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DEBUG(format,...) LogMsg(LDEBUG,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_INFO(format,...) LogMsg(LINFO,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_WARN(format,...) LogMsg(LWARN,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_ERROR(format,...) LogMsg(LERROR,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#define LOG_DUMP(format,...) LogMsg(LDUMP,__FILE__,__LINE__,__PRETTY_FUNCTION__ ,format,##__VA_ARGS__)
#endif

#ifdef LOG_STDERR
#define LOG_TRACE(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__) 
#define LOG_DEBUG(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#define LOG_INFO(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#define LOG_WARN(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#define LOG_ERROR(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#define LOG_DUMP(format,...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#endif


#endif
