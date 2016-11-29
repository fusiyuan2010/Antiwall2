#include <inside/UserConn.h>
#include <inside/RemoteConn.h>

void UserConn::Init() 
{
    rcbmap_[ACCEPTED] = &UserConn::read_accepted;
    rcbmap_[PROTOED] = &UserConn::read_protoed;
    rcbmap_[AUTHED] = &UserConn::read_authed;
    rcbmap_[CONNECTED] = &UserConn::read_connected;
}


UserConn::UserConn(struct bufferevent *bev, const string& ip, int port) 
: bev_(bev), ip_(ip), port_(port), id_(0) {
    SetState(ACCEPTED);
    remote_host_ = NULL;
    remote_port = -1;

    input_ = bufferevent_get_input(bev); 
    output_ = bufferevent_get_output(bev); 
}

UserConn::~UserConn() {
    LOG_DEBUG("[%p] destroyed & closed", this);
    // int len = evbuffer_get_length(output_);
    //if (len > 0) {
    //    LOG_ERROR("[%u] closed but with unsent data of %d bytes", id_, len);
    //}
    bufferevent_free(bev_);
}

int UserConn::read_accepted() {
    LOG_TRACE("Conn [%p] Got accepted ", this);

    /* Copy all the data from the input buffer to the output buffer. */
    unsigned char *mem = evbuffer_pullup(input_, 2);
    if (mem == NULL)
        return 0;

    if (mem[0] != 0x05 || mem[1] == 0 || mem[1] > 5) {
        //ERR
        return -1;
    }

    mem = evbuffer_pullup(input_, 2 + mem[1]);
    if (mem == NULL)
        return 0;

    bool use_auth = false;
    for(int i = 0; i < mem[1]; i++) {
        if (mem[2 + i] == 0x02) {
            use_auth = true;
            break;
        }
    }

    if (use_auth == false) {
        //ERR
        //return -1;
    }

    evbuffer_drain(input_, 2 + mem[1]);
    unsigned char reply[2];
    reply[0] = 0x05;
    //reply[1] = 0x02;
    reply[1] = 0x00;
    evbuffer_add(output_, reply, 2);
    //evbuffer_add_buffer(output, input);
    //SetState(PROTOED);

    // Now need not authentication
    SetState(AUTHED);
    return 1;
}

int UserConn::read_protoed() {
    LOG_TRACE("Conn [%p] Got protoed", this);
    unsigned char *mem = evbuffer_pullup(input_, 2);
    if (mem == NULL)
        return 0;

    if (mem[0] != 0x01 || mem[1] == 0) {
        // ERR
        return -1;
    }

    unsigned char usrlen = mem[1], pwdlen = 0;
    mem = evbuffer_pullup(input_, 2 + usrlen + 1);
    if (mem == NULL)
        return 0;

    pwdlen = mem[2 + usrlen];
    mem = evbuffer_pullup(input_, 2 + usrlen + 1 + pwdlen);
    if (mem == NULL)
        return 0;
    
    evbuffer_drain(input_, 2 + usrlen + 1 + pwdlen);
    unsigned char reply[2];
    reply[0] = 0x01;
    reply[1] = 0x00;
    evbuffer_add(output_, reply, 2);
    SetState(AUTHED);
    return 1;
}

int UserConn::read_authed() {
    LOG_TRACE("Conn [%p] Got authed", this);
    char remote_host[255];
    unsigned char *mem = evbuffer_pullup(input_, 7);
    if (mem == NULL)
        return 0;

    if (mem[0] != 0x05 || mem[1] != 0x01 || mem[2] != 0x00
            || (mem[3] != 0x01 && mem[3] != 0x03))
        return -1;
    unsigned char namelen = 0;
    uint16_t port = 0;
    if (mem[3] == 0x01) {
        namelen = 4;
        if ((mem = evbuffer_pullup(input_, 10)) == NULL)
            return 0;
        port = *(uint16_t *)(mem + 8);
        snprintf(remote_host, 16, "%d.%d.%d.%d", mem[4], mem[5], mem[6], mem[7]);
    } else {
        namelen = mem[4] + 1; // len byte included
        if ((mem = evbuffer_pullup(input_, 6 + namelen)) == NULL)
            return 0;
        port = *(uint16_t *)(mem + 4 + namelen);
        remote_host[namelen - 1] = '\0';
        memcpy(remote_host, mem + 5, namelen - 1);
    }

    evbuffer_drain(input_, namelen + 6);

    if (!g_remote_conn)
        return -1;

    id_ = g_remote_conn->MakeConnection(this, remote_host, ntohs(port));
    LOG_DEBUG("[%u] Going to connect %s: %d", id_, remote_host, ntohs(port));
    return 0;
}

int UserConn::read_connected() {
    if (g_remote_conn) {
        if (evbuffer_get_length(input_) == 0)
            return 0;
        LOG_TRACE("[%u] Relaying data to remote of len %d", id_, (int)evbuffer_get_length(input_));
        int len = evbuffer_get_length(input_);
        uint8_t *mem = evbuffer_pullup(input_, len);
        g_remote_conn->SendData(id_, mem, len);
        evbuffer_drain(input_, len);
        return 0;
    } else
        return -1;
    return 0; 
}

void UserConn::notify_connected() {
    LOG_TRACE("[%u] Got connected to remote", id_);
    SetState(CONNECTED);
    unsigned char reply[10] = {0};
    reply[0] = 0x05;
    reply[1] = 0x00;
    reply[2] = 0x00;
    reply[3] = 0x01;
    evbuffer_add(output_, reply, 10);
    read_connected();
}

void UserConn::ReadCallback(struct bufferevent *bev, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    int goon = 1;
    while(goon == 1)
        goon = (c->*(rcbmap_[c->GetState()]))();
    if (goon < 0) {
        if (g_remote_conn) 
            g_remote_conn->NotifyCloseConn(c->id_);
        delete c;
    }
}

void UserConn::WriteCallback(struct bufferevent *bev, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    int len = evbuffer_get_length(c->output_);
    if (len == 0)
        delete c;
}

void UserConn::EventCallback(struct bufferevent *bev, short events, void *ctx)
{
    UserConn *c = (UserConn*)ctx;
    if (events & BEV_EVENT_ERROR)
        LOG_WARN("[%u] Got error, close", c->id_);

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LOG_INFO("[%u] user closed connection", c->id_);
        if (g_remote_conn) {
            int len = evbuffer_get_length(c->input_);
            if (len > 0) {
                uint8_t *mem = evbuffer_pullup(c->input_,  len);
                g_remote_conn->SendData(c->id_, mem, len);
                evbuffer_drain(c->input_, len);
            }
            g_remote_conn->NotifyCloseConn(c->id_);
        }
        delete c;
    }
}

void UserConn::Close() 
{
    // Wait to sent all remaining data
    int len = evbuffer_get_length(output_);
    if (len > 0) {
        // LOG_ERROR("[%u] closed but with unsent data of %d bytes", id_, len);
        bufferevent_setcb(bev_, NULL, UserConn::WriteCallback, UserConn::EventCallback, this);
    } else 
        delete this;
}

unordered_map<int, UserConn::IOCB> UserConn::rcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::wcbmap_;
unordered_map<int, UserConn::IOCB> UserConn::evcbmap_;



