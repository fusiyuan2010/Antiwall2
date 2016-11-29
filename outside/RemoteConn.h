#ifndef _OUTSIDE_REMOTECONN_H_
#define _OUTSIDE_REMOTECONN_H_
#include <outside/Common.h>
#include <unordered_map>
#include <string>

using namespace std;

class RemoteConn : public Conn {
    struct bufferevent *bev_;
    UserConn *user_conn_;
    struct evbuffer *input_;
    struct evbuffer *output_;
    friend class UserConn;
    uint32_t id_;
    int port_;
    bool delete_after_conn_;

public:
    typedef int (RemoteConn::*IOCB)();
    enum {
        CONNECTING = 1,
        CONNECTED = 2,
    };

private:
    static unordered_map<int, IOCB> rcbmap_;
    static unordered_map<int, IOCB> wcbmap_;
    static unordered_map<int, IOCB> evcbmap_;

    int read_connected();
    void notify_user_close();
    void connect_to_addr(struct sockaddr_in *sin);

public:
    RemoteConn(struct bufferevent *bev, UserConn *user_conn, uint32_t id);
    ~RemoteConn();

    static void Init();
    int Connect(const char *addr, int port);
    void Close();
    static void EventCallback(struct bufferevent *bev, short events, void *ctx);
    static void ReadCallback(struct bufferevent *bev, void *ctx);
    static void WriteCallback(struct bufferevent *bev, void *ctx);
    static void DNSCallback(int errcode, struct evutil_addrinfo *addr, void *ptr);
};

#endif
