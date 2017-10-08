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
    LOG_DEBUG("[%p] Got user connection! from [%s:%d]", this, ip.c_str(), port);
    input_ = bufferevent_get_input(bev); 
    output_ = bufferevent_get_output(bev); 
    uint8_t key[16];
    //for(int i = 0; i < 16; i++) key[i] = 5;
    EncryptionCtx::MakeRandomKey(key, 16);
    csend_.SetKey(key, 16);
    crecv_.SetKey(key, 16);
    evbuffer_add(output_, key, 16);
    bufferevent_setcb(bev_, UserConn::ReadCallback, UserConn::WriteCallback, UserConn::EventCallback, this);
    bufferevent_enable(bev_, EV_READ|EV_WRITE);
    // try to schedule when data buffer < 64 KB
    bufferevent_setwatermark(bev_, EV_WRITE, 16 * 1024, 0);
    outside_proto_ = new OutsideProto(&csend_, &crecv_, input_, output_);
    timer_ping_ = event_new(base, -1, EV_TIMEOUT, UserConn::TimerCBPing, this);
    last_msg_ts_ = get_current_time_ms();
    last_ping_ts_ = 0;
    SetTimeout(timer_ping_, 200);
}

UserConn::~UserConn() 
{
    LOG_TRACE("[%p] User connection begin to destroy", this);
    bufferevent_free(bev_);
    for (auto i: remote_conns_) {
        // so remote conn will never make invalid ref
        i.second->user_conn_ = NULL;
        i.second->Close();
    }
    event_free(timer_ping_);
    LOG_DEBUG("[%p] User connection destroyed", this);
    delete outside_proto_;
}

void UserConn::Close() 
{
    LOG_DEBUG("[%p] User connection initiatively close", this);
    int len = evbuffer_get_length(output_);
    if (len > 0) {
        LOG_TRACE("[%p] wait write buffer clear before destory", this);
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
    LOG_TRACE("[%p] User conn begin to auth", this);

    /* Copy all the data from the input buffer to the output buffer. */
    uint8_t *mem = evbuffer_pullup(input_, 3);
    if (mem == NULL)
        return 0;
    
    mem = evbuffer_pullup(input_, 3 + mem[1] + mem[2]);
    if (mem == NULL)
        return 0;

    crecv_.Decrypt(mem + 3, mem[1] + mem[2]);
    uint8_t client_ver = mem[0];
    bool verified = true;

    string username((char *)mem + 3, (size_t)mem[1]);
    string password((char *)mem + 3 + mem[1], (size_t)mem[2]);
    // TODO verify username, pwd
    LOG_DEBUG("[%p] username: %s", this, username.c_str());
    if (password != "20150520")
        verified = false;
        

    uint8_t reply[16];
    uint8_t rnd_char = rand() % 0xFF;
    for(int i = 0; i < 16; i++) 
        reply[i] = rnd_char;

    bool authed = false;
    reply[0] = Protocol::VERSION;
    if (Protocol::VERSION != client_ver) {
        reply[1] = Protocol::LOGIN_NEW_VERSION;
        LOG_TRACE("[%p] version not match", this);
    } else if (!verified) {
        reply[1] = Protocol::LOGIN_INVALID_PWD;
        LOG_TRACE("[%p] not verified", this);
    } else {
        authed = true;
        LOG_TRACE("[%p] authed", this);
        reply[1] = Protocol::LOGIN_AUTHED;
    }
    
    csend_.Encrypt(reply, 16);
    evbuffer_drain(input_, 3 + mem[1] + mem[2]);
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
    uint8_t *mem = evbuffer_pullup(input_, 1);
    if (mem == NULL)
        return 0;

    last_msg_ts_ = get_current_time_ms();
    uint32_t id;
    if (mem[0] == Protocol::MSG_CREATE_CONN) {
        int port;
        string host;
        int ret = outside_proto_->DecCreateConn(host, port, id);
        if (ret <= 0)
            return ret;

        struct bufferevent *bev;
        bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        auto *conn = new RemoteConn(bev, this, id);
        LOG_TRACE("[%p] Got CREATE CONN Msg [id: %u, ptr: %p]", this, id, conn);
        if (conn->Connect(host.c_str(), port) < 0) {
            NotifyCloseConn(id);
            remote_conns_.erase(id);
        } else {
            remote_conns_[id] = conn;
        }
    } else if (mem[0] == Protocol::MSG_CONN_DATA) {
        string data;
        int ret = outside_proto_->DecConnData(id, data);
        if (ret <= 0)
            return ret;

        LOG_TRACE("[%p] Got CONN_DATA Msg [id:%u]", this, id);
        auto it = remote_conns_.find(id);
        if (it == remote_conns_.end()) {
            LOG_WARN("[%p] User conn cant find session for id: %u", this, id);
            NotifyCloseConn(id);
        } else {
            evbuffer_add(it->second->output_, data.c_str(), data.size());
        }
    } else if (mem[0] == Protocol::MSG_CONN_CLOSED) {
        int ret = outside_proto_->DecConnClosed(id);
        if (ret <= 0)
            return ret;

        LOG_TRACE("[%p] Got CONN_CLOSE Msg [id:%u]", this, id);
        auto it = remote_conns_.find(id);
        if (it == remote_conns_.end()) {
            LOG_WARN("[%p] User conn cant find session for id: %u", this, id);
        } else {
            it->second->Close();
            sched_.RemoveFromQueue(it->second);
            remote_conns_.erase(it);
        }
    } else if (mem[0] == Protocol::MSG_PING) {
        uint32_t key;
        int ret = outside_proto_->DecPing(key);
        if (ret <= 0)
            return ret;
        outside_proto_->EncPong(key);
    } else if (mem[0] == Protocol::MSG_PONG) {
        uint32_t key;
        int ret = outside_proto_->DecPong(key);
        if (ret <= 0)
            return ret;
        if (ping_key_ != key) {
            LOG_ERROR("[%p] Got unmatch ping key, Gonna close", this);
            return -1;
        }
        LOG_DEBUG("[%p] Ping %u ms", this, get_current_time_ms() - last_ping_ts_);
        last_ping_ts_ = 0;
    } else {
        LOG_TRACE("[%p] Got Unknow Msg , Gonna close", this);
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

void UserConn::SendData(uint32_t id, void *buf, int len) 
{
    outside_proto_->EncConnData(id, buf, len);
}

void UserConn::NotifyCloseConn(uint32_t id)
{
    LOG_TRACE("[%p] Send CLOSE CONN to user id: %u", this, id);
    outside_proto_->EncConnClosed(id);
    remote_conns_.erase(id);
}

void UserConn::NotifyConnCreated(uint32_t id)
{
    LOG_TRACE("[%p] Send CONN CREATED to user id: %u", this, id);
    outside_proto_->EncConnCreated(id);
}

void UserConn::WriteCallback(struct bufferevent *bev, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    int len = evbuffer_get_length(c->output_);
    if (len == 0) {
        if (c->going_close_) {
            LOG_DEBUG("[%p] Write buffer cleared, going to close", c);
            delete c;
            return;
        } else {
            // the user conn still alive until now
            // reset last msg time
            uint64_t now = get_current_time_ms();
            c->last_msg_ts_ = now;
            c->NotifySched();
        }
    }
}

void UserConn::TimerCBPing(evutil_socket_t fd, short what, void *ctx) 
{
    UserConn *c = (UserConn*)ctx;
    c->SetTimeout(c->timer_ping_, 200);
    uint64_t cur_ms = get_current_time_ms();
    if (c->GetState() != CONNECTED) {
        if (cur_ms - c->last_msg_ts_ > 6000) {
            LOG_DEBUG("[%p] Timeout before authed!", c);
            delete c;
            return;
        }
    } else {
        // after uthed
        if (c->last_ping_ts_) {
            // ping sent
            if (cur_ms - c->last_msg_ts_ > 9500) {
                // 1.5 + 8s timeout for ping = 9.5s
                LOG_WARN("[%p] conn ping timeout!", c);
                delete c;
                return;
            }
        } else {
            // check need ping
            if (cur_ms - c->last_msg_ts_ > 1500) {
                c->ping_key_ = rand();
                c->last_ping_ts_ = cur_ms;
                c->outside_proto_->EncPing(c->ping_key_);
            }
        }
    }
}

void UserConn::SetTimeout(struct event *timer, int ms) 
{
    struct timeval tm = {ms / 1000, (ms % 1000) * 1000};
    event_add(timer, &tm);
}


unordered_map<int, UserConn::IOCB> UserConn::rcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::wcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::evcbmap_;



