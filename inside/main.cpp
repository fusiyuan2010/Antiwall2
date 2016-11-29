#include <inside/Common.h>
#include <inside/UserConn.h>
#include <inside/RemoteConn.h>
#ifndef WIN32
#include <unistd.h>
#endif

using namespace std;


struct event_base *base = NULL;
struct evdns_base *dns_base = NULL;
RemoteConn *g_remote_conn = NULL;

// for both inbound/outbound traffic
TrafficMeter traffic_meter;

static void
accept_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    string ip;
    int port = 30;
    UserConn *c = new UserConn(bev, ip, port);
    bufferevent_setcb(bev, UserConn::ReadCallback, NULL, UserConn::EventCallback, c);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}


static void
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "Got an error %d (%s) on the listener. "
                "Shutting down.\n", err, evutil_socket_error_to_string(err));

        event_base_loopexit(base, NULL);
}

static void show_message_stdout(evutil_socket_t fd, short what, void *ctx) 
{
    (void)ctx;
    int conn_num = 0;
    if (g_remote_conn)
        conn_num = g_remote_conn->ConnNum();
    printf("\rTraffic %.1f KB/s on %d connections\t\t\t\t", 
            (float)traffic_meter.GetSpeed(5) / 1024, conn_num);
    fflush(stdout);
}


int
main(int argc, char **argv)
{
    struct evconnlistener *listener;
    struct sockaddr_in sin;

#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#else
        LogInit("inside.log", LTRACE);
#endif
    int port = 9875;
    GetLoginInfo();

    if (argc > 1)
        port = atoi(argv[1]);

    if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port");
            return 1;
    }

    srand(time(NULL));

    UserConn::Init();
    RemoteConn::Init();

    base = event_base_new();
    dns_base = evdns_base_new(base, 1);

    if (!base) {
            puts("Couldn't open event base");
            return 1;
    }

    /* Clear the sockaddr before using it, in case there are extra
     * platform-specific fields that can mess us up. */
    memset(&sin, 0, sizeof(sin));
    /* This is an INET address */
    sin.sin_family = AF_INET;
    /* Listen on 0.0.0.0 */
    sin.sin_addr.s_addr = htonl(0);
    /* Listen on the given port. */
    sin.sin_port = htons(port);

    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
            perror("Couldn't create listener");
            return 1;
    }

    
    RemoteConn *remote_conn = new RemoteConn(g_proxyip, 9999);
    remote_conn->Connect();
    evconnlistener_set_error_cb(listener, accept_error_cb);
#ifndef WIN32
    //daemon(1, 0);
#endif

    // show message to user
    struct event *traffic_meter_timer = event_new(base, -1, 
            EV_TIMEOUT | EV_PERSIST, 
            show_message_stdout, NULL);
    struct timeval tm = {1, 0};
    event_add(traffic_meter_timer, &tm);

    event_base_dispatch(base);
    event_free(traffic_meter_timer);
    return 0;
}

