#include <netinet/tcp.h>
#include <outside/Common.h>
#include <outside/UserConn.h>
#include <outside/RemoteConn.h>
#include <unistd.h>
#include <signal.h>

using namespace std;


struct event_base *base = NULL;
struct evdns_base *dns_base = NULL;

static void
accept_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    const char opt_no_delay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt_no_delay, sizeof(char));

    struct bufferevent *bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    string ip = inet_ntoa(((struct sockaddr_in *)address)->sin_addr);
    int port = ntohs(((struct sockaddr_in *)address)->sin_port);
    UserConn *c = new UserConn(bev, ip, port);
    (void)c; // use less, register itself in event loop
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


int
main(int argc, char **argv)
{
        struct evconnlistener *listener;
        struct sockaddr_in sin;
        LogInit("outside.log", LTRACE);

        int port = 80;

        if (argc > 1) {
                port = atoi(argv[1]);
        }
        if (port<=0 || port>65535) {
                puts("Invalid port");
                return 1;
        }

        signal(SIGPIPE, SIG_IGN);
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
        evconnlistener_set_error_cb(listener, accept_error_cb);

        daemon(1, 0);
        event_base_dispatch(base);
        return 0;
}

