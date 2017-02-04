#ifndef _INSIDE_COMMON_H_
#define _INSIDE_COMMON_H_
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <arpa/inet.h>
#include <event2/dns.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <common/Log.h>



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


uint64_t get_current_time_ms();

#endif

