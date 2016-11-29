#include <outside/RemoteConn.h>
#include <outside/UserConn.h>

void RemoteConn::Init() {
    rcbmap_[CONNECTED] = &RemoteConn::read_connected;
    rcbmap_[CONNECTING] = &RemoteConn::read_connected;
}

RemoteConn::RemoteConn(struct bufferevent *bev, UserConn *user_conn, uint32_t id)
    : bev_(bev), user_conn_(user_conn), id_(id), port_(-1) {
    SetState(CONNECTING);
    input_ = bufferevent_get_input(bev); 
    output_ = bufferevent_get_output(bev); 
    delete_after_conn_ = false;
    bufferevent_setwatermark(bev_, EV_READ, 0, 65536);
}


RemoteConn::~RemoteConn() 
{
    LOG_DEBUG("[%p] destroyed & closed", this);
    bufferevent_free(bev_);
}

int RemoteConn::Connect(const char *addr, int port) 
{
    LOG_TRACE("[%p] Begin to resolve [%s]", this, addr);
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    port_ = port;
    evdns_getaddrinfo(
              dns_base, addr, NULL /* no service name given */,
              &hints, RemoteConn::DNSCallback, this);
    return 0;
}

int RemoteConn::read_connected() 
{
    LOG_TRACE("[%p] Relaying data to user of len %d", this, (int)evbuffer_get_length(input_));
    user_conn_->sched_.AddToQueue(this);
    user_conn_->NotifySched();
    return 0;
}


void RemoteConn::connect_to_addr(struct sockaddr_in *sin) 
{
    bufferevent_setcb(bev_, RemoteConn::ReadCallback, NULL, RemoteConn::EventCallback, this);
    bufferevent_enable(bev_, EV_READ|EV_WRITE);
    if (bufferevent_socket_connect(bev_,
        (struct sockaddr *)sin, sizeof(*sin)) < 0) {
        /* Error starting connection */
        LOG_INFO("[%p] Fail to connecting remote", this);
        notify_user_close();
        delete this;
    }
}


void RemoteConn::DNSCallback(int errcode, struct evutil_addrinfo *addr, void *ctx) 
{
    RemoteConn *c = (RemoteConn*)ctx;

    // the conn should have been closed while DNS resolving. need not care the result
    if (c->delete_after_conn_) {
        if (addr) // addr is NULL in case of error
            evutil_freeaddrinfo(addr);
        delete c;
        return;
    }

    if (errcode) {
        LOG_INFO("[%p] DNS Resolve failed with error %s",
                c, evutil_gai_strerror(errcode));
        c->notify_user_close();
        delete c;
    } else {
        bool valid_addr = false;
        struct evutil_addrinfo *ai;
        for (ai = addr; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                valid_addr = true;
                sin->sin_port = htons(c->port_);
                c->connect_to_addr(sin);
            }
            break;
        }
        evutil_freeaddrinfo(addr);
        if (!valid_addr) {
            c->notify_user_close();
            delete c;
        } else
            LOG_TRACE("[%p] Begin to connect", c);
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
        c->notify_user_close();
        delete c;
    }
}

void RemoteConn::EventCallback(struct bufferevent *bev, short events, void *ctx)
{
    RemoteConn *c = (RemoteConn*)ctx;
    if (events & BEV_EVENT_CONNECTED) {
        LOG_TRACE("[%p] Got connected callback.", c);
        c->SetState(RemoteConn::CONNECTED);
        c->user_conn_->NotifyConnCreated(c->id_);
    }

    if (events & BEV_EVENT_ERROR)
        LOG_WARN("[%p] Got error, close", c);

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        int len = evbuffer_get_length(c->input_);
        if (len > 0) {
            uint8_t *mem = evbuffer_pullup(c->input_,  len);
            c->user_conn_->SendData(c->id_, mem, len);
            evbuffer_drain(c->input_, len);
        }
        c->notify_user_close();
        delete c;
    }
}

void RemoteConn::WriteCallback(struct bufferevent *bev, void *ctx)
{
    RemoteConn *c = (RemoteConn*)ctx;
    int len = evbuffer_get_length(c->output_);
    if (len == 0)
        delete c;
}


void RemoteConn::Close() 
{
    // Wait to sent all remaining data
    int len = evbuffer_get_length(output_);

    // have to wait DNS called back to delete
    if (GetState() == CONNECTING) {
        delete_after_conn_ = true;
        return;
    }

    if (len > 0) {
        // LOG_ERROR("[%u] closed but with unsent data of %d bytes", id_, len);
        bufferevent_setcb(bev_, NULL, RemoteConn::WriteCallback, RemoteConn::EventCallback, this);
    } else {
        delete this;
    }
}


void RemoteConn::notify_user_close() {
    user_conn_->sched_.RemoveFromQueue(this);
    user_conn_->NotifyCloseConn(id_);
}

unordered_map<int, RemoteConn::IOCB> RemoteConn::rcbmap_;
unordered_map<int, RemoteConn::IOCB> RemoteConn::wcbmap_;
unordered_map<int, RemoteConn::IOCB> RemoteConn::evcbmap_;


