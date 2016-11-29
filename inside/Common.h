#ifndef _INSIDE_COMMON_H_
#define _INSIDE_COMMON_H_
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <event2/dns.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <common/Log.h>
#include <common/TrafficMeter.h>
#include <string>



class Conn {
    int state_;
    int conn_type_;

public:
    int GetState() { return state_; }
    void SetState(int state) { state_ = state; }
};

class UserConn;
class RemoteConn;

extern struct event_base *base;
extern struct evdns_base *dns_base;
extern RemoteConn *g_remote_conn;
extern std::string g_username;
extern std::string g_password;
extern std::string g_proxyip;

// for both inbound/outbound traffic
extern TrafficMeter traffic_meter;


uint64_t get_current_time_ms();

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap);
int c99_snprintf(char *outBuf, size_t size, const char *format, ...);
#endif

void GetLoginInfo();

#endif

