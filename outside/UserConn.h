#ifndef _OUTSIDE_USERCONN_H_
#define _OUTSIDE_USERCONN_H_
#include <outside/Common.h>
#include <outside/Scheduler.h>
#include <unordered_map>
#include <string>
#include <common/EncryptionCtx.h>

using namespace std;

class RemoteConn;

class UserConn : public Conn {
    struct bufferevent *bev_;
    const string ip_;
    const int port_;
    unordered_map<uint32_t, RemoteConn *> remote_conns_;
    struct evbuffer *input_;
    struct evbuffer *output_;
    bool going_close_;

    EncryptionCtx csend_;
    EncryptionCtx crecv_;
    Scheduler sched_;
    friend class RemoteConn;

public:
    typedef int (UserConn::*IOCB)();

private:
    static unordered_map<int, IOCB> rcbmap_;
    static unordered_map<int, IOCB> wcbmap_;
    static unordered_map<int, IOCB> evcbmap_;
    int read_accepted();
    int read_connected();

public:
    enum {
        ACCEPTED = 1,
        CONNECTED = 2,
    };

    static const int WRITE_BUF_LIMIT = 32 * 1024;

    static void Init();
    void SendData(uint32_t id, void *buf, int len);
    void NotifyCloseConn(uint32_t id);
    void NotifyConnCreated(uint32_t id);
    void Close();
    void NotifySched();

    UserConn(struct bufferevent *bev, const string& ip, int port);
    ~UserConn();


    static void ReadCallback(struct bufferevent *bev, void *ctx);
    static void WriteCallback(struct bufferevent *bev, void *ctx);
    static void EventCallback(struct bufferevent *bev, short events, void *ctx);
};

#endif

