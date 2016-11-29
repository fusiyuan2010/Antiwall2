#include <common/Protocol.h>
#include <common/EncryptionCtx.h>


OutsideProto::OutsideProto(EncryptionCtx *csend,
        EncryptionCtx *crecv, 
        struct evbuffer *input, 
        struct evbuffer *output):
    csend_(csend), crecv_(crecv), input_(input), output_(output) {
}

void OutsideProto::EncCreateConn(const char *addr, int port, uint32_t id) {
    int addrlen = strlen(addr);
    uint8_t *buf = new uint8_t[8 + addrlen]; 
    // type 1B, ID 4B, port 2B, addrlen 1B
    buf[0] = Protocol::MSG_CREATE_CONN;
    buf[1] = (id >> 24) & 0xFF;
    buf[2] = (id >> 16) & 0xFF;
    buf[3] = (id >> 8) & 0xFF;
    buf[4] = (id >> 0) & 0xFF;
    buf[5] = addrlen;
    buf[6] = (port >> 8);
    buf[7] = port & 0xFF;
    memcpy(buf + 8, addr, addrlen);
    // encrypt begins after addrlen byte
    csend_->Encrypt(buf + 6, addrlen + 2);
    evbuffer_add(output_, buf, 8 + addrlen);
    delete[] buf;
}

int OutsideProto::DecCreateConn(string &addr, int &port, uint32_t &id) {
    uint8_t *mem = evbuffer_pullup(input_, 6);
    if (mem == NULL)
        return 0;

    id = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];
    int addrlen = mem[5];
    mem = evbuffer_pullup(input_, 8 + addrlen);
    if (mem == NULL)
        return 0;
    crecv_->Decrypt(mem + 6, addrlen + 2);
    port = (mem[6] << 8) + mem[7];

    char *tmpbuf = new char[addrlen + 1];
    memcpy(tmpbuf , mem + 8, addrlen);
    tmpbuf[addrlen] = '\0';

    addr.assign(tmpbuf);
    delete[] tmpbuf;
    evbuffer_drain(input_, 8 + addrlen);
    return 1;
}

void OutsideProto::EncConnCreated(uint32_t id) {
    uint8_t reply[5];
    reply[0] = Protocol::MSG_CONN_CREATED;
    reply[1] = (id >> 24) & 0xFF;
    reply[2] = (id >> 16) & 0xFF;
    reply[3] = (id >> 8) & 0xFF;
    reply[4] = (id >> 0) & 0xFF;
    csend_->Encrypt(reply + 1, 4);
    evbuffer_add(output_, reply, 5);
}

int OutsideProto::DecConnCreated(uint32_t &id) {
    uint8_t *mem = evbuffer_pullup(input_, 5);
    if (mem == NULL)
        return 0;
    crecv_->Decrypt(mem + 1, 4);
    id = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];
    evbuffer_drain(input_, 5);
    return 1;
}

void OutsideProto::EncConnClosed(uint32_t id) {
    uint8_t reply[5];
    reply[0] = Protocol::MSG_CONN_CLOSED;
    reply[1] = (id >> 24) & 0xFF;
    reply[2] = (id >> 16) & 0xFF;
    reply[3] = (id >> 8) & 0xFF;
    reply[4] = (id >> 0) & 0xFF;
    csend_->Encrypt(reply + 1, 4);
    evbuffer_add(output_, reply, 5);
}

int OutsideProto::DecConnClosed(uint32_t &id) {
    uint8_t *mem = evbuffer_pullup(input_, 5);
    if (mem == NULL)
        return 0;

    crecv_->Decrypt(mem + 1, 4);
    id = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];

    evbuffer_drain(input_, 5);
    return 1;
}

void OutsideProto::EncPing(uint32_t key) {
    uint8_t reply[5];
    reply[0] = Protocol::MSG_PING;
    reply[1] = (key >> 24) & 0xFF;
    reply[2] = (key >> 16) & 0xFF;
    reply[3] = (key >> 8) & 0xFF;
    reply[4] = (key >> 0) & 0xFF;
    evbuffer_add(output_, reply, 5);
}

int OutsideProto::DecPing(uint32_t &key) {
    uint8_t *mem = evbuffer_pullup(input_, 5);
    if (mem == NULL)
        return 0;

    key = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];

    evbuffer_drain(input_, 5);
    return 1;
}

void OutsideProto::EncPong(uint32_t key) {
    uint8_t reply[5];
    reply[0] = Protocol::MSG_PONG;
    reply[1] = (key >> 24) & 0xFF;
    reply[2] = (key >> 16) & 0xFF;
    reply[3] = (key >> 8) & 0xFF;
    reply[4] = (key >> 0) & 0xFF;
    evbuffer_add(output_, reply, 5);
}

int OutsideProto::DecPong(uint32_t &key) {
    uint8_t *mem = evbuffer_pullup(input_, 5);
    if (mem == NULL)
        return 0;

    key = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];

    evbuffer_drain(input_, 5);
    return 1;
}

void OutsideProto::EncConnData(uint32_t id, void *_buf, uint32_t len) {
    char *buf = (char *)_buf;
    csend_->Encrypt(buf, len);
    for(uint32_t prog = 0; prog < len; ) {
        // maximum size of a packet is 65535
        uint32_t curlen = len - prog > 65535? 65535 : len - prog;
        uint8_t reply[7];
        reply[0] = Protocol::MSG_CONN_DATA;
        reply[1] = (id >> 24) & 0xFF;
        reply[2] = (id >> 16) & 0xFF;
        reply[3] = (id >> 8) & 0xFF;
        reply[4] = (id >> 0) & 0xFF;
        reply[5] = (curlen >> 8) & 0xFF;
        reply[6] = (curlen >> 0) & 0xFF;
        evbuffer_add(output_, reply, 7);
        evbuffer_add(output_, buf + prog, curlen);
        prog += curlen;
    }
}

int OutsideProto::DecConnData(uint32_t &id, string &data) {
    uint8_t *mem = evbuffer_pullup(input_, 7);
    if (mem == NULL)
        return 0;

    id = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + mem[4];

    uint32_t len = (mem[5] << 8) + mem[6];
    mem = evbuffer_pullup(input_, 7 + len);
    if (mem == NULL)
        return 0;
    crecv_->Decrypt(mem + 7, len);
    data.assign((char *)(mem + 7), size_t(len));
    evbuffer_drain(input_, 7 + len);
    return 1;
}


