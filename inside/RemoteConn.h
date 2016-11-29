#ifndef _INSIDE_REMOTECONN_H_
#define _INSIDE_REMOTECONN_H_
#include <inside/Common.h>
#include <unordered_map>
#include <string>
#include <stdint.h>
#include <common/EncryptionCtx.h>
#include <common/Protocol.h>

using namespace std;

class RemoteConn : public Conn {
    struct bufferevent *bev_;
    unordered_map<uint32_t, UserConn *> user_conns_;
    struct evbuffer *input_;
    struct evbuffer *output_;
    friend class UserConn;
    string remote_addr_;
    int remote_port_;
    EncryptionCtx csend_;
    EncryptionCtx crecv_;
    uint32_t gid_;
    struct event *timer_reconn_;
    struct event *timer_ping_;
    OutsideProto *outside_proto_;

    // last ts of receiving a message from outside
    uint64_t last_msg_ts_;
    uint64_t last_ping_ts_;
    uint32_t ping_key_;

public:
    typedef int (RemoteConn::*IOCB)();
    enum {
        CREATED,
        CONNECTING,
        CONNECTED,
        WAITING_AUTH_REPLY,
        AUTHED,
    };

private:
    static unordered_map<int, IOCB> rcbmap_;
    static unordered_map<int, IOCB> wcbmap_;
    static unordered_map<int, IOCB> evcbmap_;

    int read_authed();
    int read_connected();
    int read_waiting_auth_reply();
    void connect_to_addr(struct sockaddr_in *sin);
    void destroy_myself(bool reconnect);

public:
    RemoteConn(const string& addr, int port);
    ~RemoteConn();

    static void Init();
    int Connect();
    int ConnNum();
    uint32_t MakeConnection(UserConn *conn, const char *addr, int port);
    void NotifyCloseConn(uint32_t id);
    void SendData(uint32_t id, void *buf, int len);
    void SetTimeout(struct event *timer, int ms);
    static void EventCallback(struct bufferevent *bev, short events, void *ctx);
    static void ReadCallback(struct bufferevent *bev, void *ctx);
    static void DNSCallback(int errcode, struct evutil_addrinfo *addr, void *ptr);
    static void TimerCBReconn(evutil_socket_t fd, short what, void *ctx);
    static void TimerCBPing(evutil_socket_t fd, short what, void *ctx);
};

#endif
