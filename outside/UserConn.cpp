#include <outside/UserConn.h>
#include <outside/RemoteConn.h>
#include <common/Protocol.h>

void UserConn::Init() 
{
    rcbmap_[ACCEPTED] = &UserConn::read_accepted;
    rcbmap_[CONNECTED] = &UserConn::read_connected;
}


UserConn::UserConn(struct bufferevent *bev, const string& ip, int port) 
: bev_(bev), ip_(ip), port_(port), going_close_(false) {
    SetState(ACCEPTED);

    input_ = bufferevent_get_input(bev); 
    output_ = bufferevent_get_output(bev); 
    uint8_t key[16];
    EncryptionCtx::MakeRandomKey(key, 16);
    csend_.SetKey(key, 16);
    crecv_.SetKey(key, 16);
    evbuffer_add(output_, key, 16);
    bufferevent_setcb(bev_, UserConn::ReadCallback, UserConn::WriteCallback, UserConn::EventCallback, this);
    bufferevent_enable(bev_, EV_READ|EV_WRITE);
    // try to schedule when data buffer < 64 KB
    bufferevent_setwatermark(bev_, EV_WRITE, 16 * 1024, 0);
}

UserConn::~UserConn() 
{
    LOG_DEBUG("[%p] User conn destroyed & closed", this);
    bufferevent_free(bev_);
    for (auto i: remote_conns_) {
        i.second->Close();
    }
}

void UserConn::Close() 
{
    int len = evbuffer_get_length(output_);
    if (len > 0) {
        // LOG_ERROR("[%u] closed but with unsent data of %d bytes", id_, len);
        going_close_ = true;
    } else {
        delete this;
    }
}

void UserConn::NotifySched() 
{
    int len = evbuffer_get_length(output_);
    while(len < WRITE_BUF_LIMIT) {
        RemoteConn *conn = sched_.Schedule();
        if (conn == NULL)
            break;

        int len2 = evbuffer_get_length(conn->input_);
        int send_len = len2 > 8192 ? 8192 : len2;
        uint8_t *mem = evbuffer_pullup(conn->input_,  send_len);
        SendData(conn->id_, mem, send_len);
        evbuffer_drain(conn->input_, send_len);
        if (len2 > send_len)
            sched_.AddToQueue(conn);
        len = evbuffer_get_length(output_);
    }
}

int UserConn::read_accepted() {
    LOG_TRACE("User conn [%p] Got accepted ", this);

    /* Copy all the data from the input buffer to the output buffer. */
    uint8_t *mem = evbuffer_pullup(input_, 3);
    if (mem == NULL)
        return 0;
    
    mem = evbuffer_pullup(input_, 3 + mem[1] + mem[2]);
    if (mem == NULL)
        return 0;

    crecv_.Decrypt(mem + 3, mem[1] + mem[2]);
    evbuffer_drain(input_, 3 + mem[1] + mem[2]);

    
    uint8_t client_ver = mem[0];
    bool verified = true;
    // TODO verify username, pwd
    uint8_t reply[16];
    uint8_t rnd_char = rand() % 0xFF;
    for(int i = 0; i < 16; i++) 
        reply[i] = rnd_char;

    bool authed = false;
    reply[0] = Protocol::VERSION;
    if (Protocol::VERSION != client_ver) {
        reply[1] = Protocol::LOGIN_NEW_VERSION;
        LOG_TRACE("version not match");
    } else if (!verified) {
        reply[1] = Protocol::LOGIN_INVALID_PWD;
        LOG_TRACE("not verified");
    } else {
        authed = true;
        LOG_TRACE("authed");
        reply[1] = Protocol::LOGIN_AUTHED;
    }
    
    csend_.Encrypt(reply, 16);
    evbuffer_add(output_, reply, 16);
    if (authed == true) {
        SetState(CONNECTED);
        return 1;
    } else {
        Close();
        return 0;
    }
}

int UserConn::read_connected() {
    uint8_t *mem = evbuffer_pullup(input_, 5);
    if (mem == NULL)
        return 0;

    uint32_t id = (mem[1] << 24)
        + (mem[2] << 16)
        + (mem[3] << 8)
        + (mem[4]);
    
    if (mem[0] == Protocol::MSG_CREATE_CONN) {
        LOG_TRACE("Got CREATE CONN Msg [id:%u]", id);
        mem = evbuffer_pullup(input_, 6);
        if (mem == NULL)
            return 0;
        int addrlen = mem[5];
        mem = evbuffer_pullup(input_, 8 + addrlen);
        if (mem == NULL)
            return 0;
        crecv_.Decrypt(mem + 6, addrlen + 2);
        int port = (mem[6] << 8) + mem[7];
        char remote_host[addrlen + 1];
        memcpy(remote_host, mem + 8, addrlen);
        remote_host[addrlen] = '\0';

        struct bufferevent *bev;
        bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        auto *conn = new RemoteConn(bev, this, id);
        if (conn->Connect(remote_host, port) < 0) {
            NotifyCloseConn(id);
            remote_conns_.erase(id);
        } else {
            remote_conns_[id] = conn;
        }
        evbuffer_drain(input_, 8 + addrlen);
    } else if (mem[0] == Protocol::MSG_CONN_DATA) {
        LOG_TRACE("Got CONN_DATA Msg [id:%u]", id);
        mem = evbuffer_pullup(input_, 7);
        if (mem == NULL)
            return 0;
        int msglen = (mem[5] << 8) + mem[6];
        mem = evbuffer_pullup(input_, 7 + msglen);
        if (mem == NULL)
            return 0;
        crecv_.Decrypt(mem + 7, msglen);
        auto it = remote_conns_.find(id);
        if (it == remote_conns_.end()) {
            LOG_WARN("[%p] User conn cant find session for id: %u", this, id);
            NotifyCloseConn(id);
        } else {
            evbuffer_add(it->second->output_, mem + 7, msglen);
        }
        evbuffer_drain(input_, 7 + msglen);
    } else if (mem[0] == Protocol::MSG_CONN_CLOSED) {
        LOG_TRACE("Got CONN_CLOSE Msg [id:%u]", id);
        auto it = remote_conns_.find(id);
        if (it == remote_conns_.end()) {
            LOG_WARN("[%p] User conn cant find session for id: %u", this, id);
        } else {
            it->second->Close();
            sched_.RemoveFromQueue(it->second);
            remote_conns_.erase(it);
        }
        evbuffer_drain(input_, 5);
    } else {
        LOG_TRACE("Got Unknow Msg [id:%u], Gonna close", id);
        return -1;
    }
    return 1;
}

void UserConn::ReadCallback(struct bufferevent *bev, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    int goon = 1;
    while(goon == 1)
        goon = (c->*(rcbmap_[c->GetState()]))();
    if (goon < 0) {
        delete c;
    }
}

void UserConn::EventCallback(struct bufferevent *bev, short events, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    if (events & BEV_EVENT_ERROR)
        LOG_WARN("[%p] User conn Got error, close", c);

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        delete c;
    }
}

void UserConn::SendData(uint32_t id, void *_buf, int len) 
{
    char *buf = (char *)_buf;
    csend_.Encrypt(buf, len);
    for(int prog = 0; prog < len; ) {
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

void UserConn::NotifyCloseConn(uint32_t id)
{
    uint8_t reply[5];
    reply[0] = Protocol::MSG_CONN_CLOSED;
    reply[1] = (id >> 24) & 0xFF;
    reply[2] = (id >> 16) & 0xFF;
    reply[3] = (id >> 8) & 0xFF;
    reply[4] = (id >> 0) & 0xFF;
    evbuffer_add(output_, reply, 5);
    remote_conns_.erase(id);
}

void UserConn::NotifyConnCreated(uint32_t id)
{
    uint8_t reply[5];
    reply[0] = Protocol::MSG_CONN_CREATED;
    reply[1] = (id >> 24) & 0xFF;
    reply[2] = (id >> 16) & 0xFF;
    reply[3] = (id >> 8) & 0xFF;
    reply[4] = (id >> 0) & 0xFF;
    evbuffer_add(output_, reply, 5);
}

void UserConn::WriteCallback(struct bufferevent *bev, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    int len = evbuffer_get_length(c->output_);
    if (len == 0) {
        if (c->going_close_) {
            delete c;
            return;
        } else {
            c->NotifySched();
        }
    }
}


unordered_map<int, UserConn::IOCB> UserConn::rcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::wcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::evcbmap_;



