#ifndef _COMMON_PROTOCOL_H_
#define _COMMON_PROTOCOL_H_
#include <cstdlib>
#include <cstring>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <stdint.h>

class Protocol {
public:
    static const int VERSION = 2;

    enum LoginReturnType {
        LOGIN_AUTHED = 1,
        LOGIN_NEW_VERSION = 2,
        LOGIN_INVALID_PWD = 3,
        LOGIN_OUT_OF_DATA = 4,
    };

    enum OutsideMessageType {
        MSG_CREATE_CONN = 2,
        MSG_CONN_CREATED = 3,
        MSG_CONN_CLOSED = 4,
        MSG_CONN_DATA = 5,
        MSG_PING = 6,
        MSG_PONG = 7,
    };

};


#include <string>
using std::string;

class EncryptionCtx;

//ServerMessage
class OutsideProto {
private:
    EncryptionCtx *csend_;
    EncryptionCtx *crecv_;
    struct evbuffer *input_;
    struct evbuffer *output_;
    
public:
    OutsideProto(EncryptionCtx *csend,
            EncryptionCtx *crecv, 
            struct evbuffer *input, 
            struct evbuffer *output);

    void EncCreateConn(const char *addr, int port, uint32_t id);
    int DecCreateConn(string &addr, int &port, uint32_t& id);

    void EncConnCreated(uint32_t id);
    int DecConnCreated(uint32_t &id);

    void EncConnClosed(uint32_t id);
    int DecConnClosed(uint32_t &id);
    
    void EncPing(uint32_t key);
    int DecPing(uint32_t &key);

    void EncPong(uint32_t key);
    int DecPong(uint32_t &key);

    void EncConnData(uint32_t id, void *buf, uint32_t len);
    int DecConnData(uint32_t &id, string &data);
};


class MasterProto {
    //void EncStatus();
};



#endif

