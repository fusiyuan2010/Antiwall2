#include <inside/RemoteConn.h>
#include <inside/UserConn.h>
#include <common/Protocol.h>
#include <common/Log.h>
#include <cstring>
#include <ctime>
#include <cstdlib>

static int reconn_timeout = 250;

void RemoteConn::Init() {
    rcbmap_[CONNECTED] = &RemoteConn::read_connected;
    rcbmap_[AUTHED] = &RemoteConn::read_authed;
    rcbmap_[WAITING_AUTH_REPLY] = &RemoteConn::read_waiting_auth_reply;
}

RemoteConn::RemoteConn(const string& addr, int port)
    : remote_addr_(addr), remote_port_(port), gid_(1) {
    bev_ = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    SetState(CREATED);
    input_ = bufferevent_get_input(bev_); 
    output_ = bufferevent_get_output(bev_); 
    timer_reconn_ = event_new(base, -1, EV_TIMEOUT, RemoteConn::TimerCBReconn, this);
    timer_ping_ = event_new(base, -1, EV_TIMEOUT, RemoteConn::TimerCBPing, this);
    outside_proto_ = new OutsideProto(&csend_, &crecv_, input_, output_);
}


RemoteConn::~RemoteConn() 
{
    LOG_DEBUG("Remote conn destroyed & closed");
    bufferevent_free(bev_);
    for (unordered_map<uint32_t, UserConn *>::iterator it = user_conns_.begin();
        it != user_conns_.end(); it++) {
        delete it->second;
    }
    event_free(timer_reconn_);
    event_free(timer_ping_);
    g_remote_conn = NULL;
    delete outside_proto_;
}


int RemoteConn::Connect() 
{
    LOG_TRACE("Remote conn Begin to resolve [%s]", remote_addr_.c_str());
	printf("Connecting to %s ...\t\t\t\t \n", g_proxyip.c_str());
    SetState(CONNECTING);
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    evdns_getaddrinfo(
              dns_base, remote_addr_.c_str(), NULL /* no service name given */,
              &hints, RemoteConn::DNSCallback, this);
    last_msg_ts_ = get_current_time_ms();
    last_ping_ts_ = 0;
    SetTimeout(timer_ping_, 1000);
    return 0;
}

int RemoteConn::ConnNum()
{
    return (int)user_conns_.size();
}

int RemoteConn::read_connected() 
{
    uint8_t *mem = evbuffer_pullup(input_, 16);
    if (mem == NULL)
        return 0;
    
	printf("Connected to remote, handshaking ...\t\t\t\t \n");
    csend_.SetKey(mem, 16);
    crecv_.SetKey(mem, 16);
    LOG_INFO("Got Server Key");


    // send usr and ::g_password
    char *buf = new char[3 + ::g_username.size() + ::g_password.size()];
    buf[0] = Protocol::VERSION;
    buf[1] = ::g_username.size();
    buf[2] = ::g_password.size();
    memcpy(buf + 3, ::g_username.c_str(), ::g_username.size());
    memcpy(buf + 3 + ::g_username.size(), ::g_password.c_str(), ::g_password.size());
    csend_.Encrypt(buf + 3, ::g_username.size() + ::g_password.size());
    
    evbuffer_add(output_, buf, 3 + g_username.size() + ::g_password.size());
    delete[] buf;
    evbuffer_drain(input_, 16);
    SetState(WAITING_AUTH_REPLY);
    return 1;
}


int RemoteConn::read_waiting_auth_reply()
{
    uint8_t *mem = evbuffer_pullup(input_, 16);
    if (mem == NULL)
        return 0;
    
    crecv_.Decrypt(mem, 16);
    if (mem[1] == Protocol::LOGIN_AUTHED) {
        g_remote_conn = this;
        SetState(AUTHED);
        LOG_INFO("Remote server auth succeed\n");
		printf("Authentication passed!\t\t\t\t \n");
        evbuffer_drain(input_, 16);
        return 1;
    } else {
        evbuffer_drain(input_, 16);
        printf("Password invalid\n");
        exit(1);
        LOG_ERROR("Auth failed: %d\n", mem[1]);
        delete this;
        return 0;
    }
}


int RemoteConn::read_authed() 
{
    uint8_t *mem = evbuffer_pullup(input_, 1);
    if (mem == NULL)
        return 0;

    last_msg_ts_ = get_current_time_ms();
    uint32_t id;
    if (mem[0] == Protocol::MSG_CONN_CLOSED) {
        // close connection of id
        int ret = outside_proto_->DecConnClosed(id);
        if (ret <= 0)
            return ret;

        LOG_TRACE("Got CONN_CLOSE Msg [id:%u]", id);
        auto it = user_conns_.find(id);
        if (it == user_conns_.end()) {
            LOG_WARN("Did not find session for %u", id);
        } else {
            it->second->Close();
            user_conns_.erase(it);
        }
    } else if (mem[0] == Protocol::MSG_CONN_CREATED) {
        int ret = outside_proto_->DecConnCreated(id);
        if (ret <= 0)
            return ret;

        LOG_TRACE("Got CONN_CREATED Msg [id:%u]", id);
        // inform connected of id
        auto it = user_conns_.find(id);
        if (it == user_conns_.end()) {
            LOG_WARN("Did not find session for %u", id);
        } else
            it->second->notify_connected();
    } else if (mem[0] == Protocol::MSG_CONN_DATA) {
        string data;
        int ret = outside_proto_->DecConnData(id, data);
        if (ret <= 0)
            return ret;

        traffic_meter.UpdateSample(data.size());
        auto it = user_conns_.find(id);
        if (it == user_conns_.end()) {
            LOG_WARN("Did not find session for %u", id);
        } else {
            evbuffer_add(it->second->output_, data.c_str(), data.size());
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
            LOG_ERROR("Got unmatch ping key, Gonna close");
            return -1;
        }
        LOG_DEBUG("Ping %u ms", get_current_time_ms() - last_ping_ts_);
        last_ping_ts_ = 0;
    } else {
        LOG_ERROR("Got Unknow Msg [id:%u], Gonna close", id);
        return -1;
    }

    return 1;
}


void RemoteConn::connect_to_addr(struct sockaddr_in *sin) 
{
    bufferevent_setcb(bev_, RemoteConn::ReadCallback, NULL, RemoteConn::EventCallback, this);
    bufferevent_enable(bev_, EV_READ|EV_WRITE);
    if (bufferevent_socket_connect(bev_,
        (struct sockaddr *)sin, sizeof(*sin)) < 0) {
        /* Error starting connection */
        LOG_INFO("Remote conn Fail to connecting remote");
        delete this;
    }
}


void RemoteConn::DNSCallback(int errcode, struct evutil_addrinfo *addr, void *ctx) 
{
    RemoteConn *c = (RemoteConn*)ctx;
    if (errcode) {
        LOG_INFO("Remote conn DNS Resolve failed with error %s",
                 evutil_gai_strerror(errcode));
        delete c;
    } else {
        bool valid_addr = false;
        struct evutil_addrinfo *ai;
        for (ai = addr; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                valid_addr = true;
                sin->sin_port = htons(c->remote_port_);
                c->connect_to_addr(sin);
            }
            break;
        }
        evutil_freeaddrinfo(addr);
        if (!valid_addr)
            delete c;
        else
            LOG_TRACE("Remote Conn Begin to connect", c);
    }
}


void RemoteConn::ReadCallback(struct bufferevent *bev, void *ctx)
{
    RemoteConn *c = (RemoteConn*)ctx;
    int goon = 1;
    while(goon == 1) {
        if (rcbmap_.count(c->GetState()) == 0) {
            goon = 0;
        } else
            goon = (c->*(rcbmap_[c->GetState()]))();
    }
    if (goon < 0) {
        delete c;
    }
}

void RemoteConn::destroy_myself(bool reconnect)
{
    if (reconnect) {
        RemoteConn *new_c = new RemoteConn(remote_addr_, remote_port_);
        delete this;
        reconn_timeout *= 2;
        if (reconn_timeout > 300 * 1000) 
            reconn_timeout = 300 * 1000;
        LOG_INFO("Remote conn broke, wait %d seconds to reconnect", reconn_timeout / 1000);
        new_c->SetTimeout(new_c->timer_reconn_, reconn_timeout);
    } else 
        delete this;
}

void RemoteConn::EventCallback(struct bufferevent *bev, short events, void *ctx)
{
    RemoteConn *c = (RemoteConn*)ctx;
    if (events & BEV_EVENT_CONNECTED) {
        LOG_TRACE("[%p] Got connected callback.", c);
        c->SetState(RemoteConn::CONNECTED);
        reconn_timeout = 250;
    }

    if (events & BEV_EVENT_ERROR)
        LOG_WARN("Remote conn Got error, close");

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        g_remote_conn = NULL;
        LOG_WARN("Remote conn gonna close");
        c->destroy_myself(true);
    }
}

void RemoteConn::TimerCBReconn(evutil_socket_t fd, short what, void *ctx) 
{
    RemoteConn *c = (RemoteConn*)ctx;
    if (c->GetState() == CREATED) {
        c->Connect();
    }
}

void RemoteConn::TimerCBPing(evutil_socket_t fd, short what, void *ctx) 
{
    RemoteConn *c = (RemoteConn*)ctx;
    c->SetTimeout(c->timer_ping_, 1000);
    uint64_t cur_ms = get_current_time_ms();
    if (c->GetState() != AUTHED) {
        if (cur_ms - c->last_msg_ts_ > 6000) {
            LOG_DEBUG("Timeout before authed!");
            c->destroy_myself(true);
            return;
        }
    } else {
        // after uthed
        if (c->last_ping_ts_) {
            // ping sent
            if (cur_ms - c->last_ping_ts_ > 3000) {
                LOG_WARN("conn timeout!");
                c->destroy_myself(true);
                return;
            }
        } else {
            // check need ping
            if (cur_ms - c->last_msg_ts_ > 8000) {
                c->ping_key_ = rand();
                c->last_ping_ts_ = cur_ms;
                c->outside_proto_->EncPing(c->ping_key_);
            }
        }
    }
}

uint32_t RemoteConn::MakeConnection(UserConn *conn, const char *addr, int port)
{
    uint32_t ret = gid_++;
    user_conns_[ret] = conn;
    outside_proto_->EncCreateConn(addr, port, ret);
    return ret;
}

void RemoteConn::NotifyCloseConn(uint32_t id) 
{
    outside_proto_->EncConnClosed(id);
    user_conns_.erase(id);
}

void RemoteConn::SendData(uint32_t id, void *buf, int len) 
{
    outside_proto_->EncConnData(id, buf, len);
    traffic_meter.UpdateSample(len);
}

void RemoteConn::SetTimeout(struct event *timer, int ms) 
{
    struct timeval tm = {ms / 1000, (ms % 1000) * 1000};
    event_add(timer, &tm);
}


unordered_map<int, RemoteConn::IOCB> RemoteConn::rcbmap_;
unordered_map<int, RemoteConn::IOCB> RemoteConn::wcbmap_;
unordered_map<int, RemoteConn::IOCB> RemoteConn::evcbmap_;


