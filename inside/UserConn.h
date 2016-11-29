#ifndef _INSIDE_USERCONN_H_
#define _INSIDE_USERCONN_H_
#include <inside/Common.h>
#include <unordered_map>
#include <string>
#include <stdint.h>

using namespace std;

class UserConn : public Conn {
    char *remote_host_;
    int remote_port;
    struct bufferevent *bev_;
    const string ip_;
    const int port_;
    uint32_t id_;
    struct evbuffer *input_;
    struct evbuffer *output_;
    friend class RemoteConn;

public:
    typedef int (UserConn::*IOCB)();

private:
    static unordered_map<int, IOCB> rcbmap_;
    static unordered_map<int, IOCB> wcbmap_;
    static unordered_map<int, IOCB> evcbmap_;
    int read_accepted();
    int read_protoed();
    int read_authed();
    int read_connected();
    void notify_connected();

public:
    enum {
    ACCEPTED = 1,
    PROTOED = 2,
    AUTHED = 3,
    CONNECTED = 4,
    };

    static void Init();

    UserConn(struct bufferevent *bev, const string& ip, int port);
    ~UserConn();
    void Close();

    static void ReadCallback(struct bufferevent *bev, void *ctx);
    static void WriteCallback(struct bufferevent *bev, void *ctx);
    static void EventCallback(struct bufferevent *bev, short events, void *ctx);
};

#endif

