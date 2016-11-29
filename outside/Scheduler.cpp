#include <outside/Scheduler.h>


void Scheduler::AddToQueue(RemoteConn *conn)
{
    if (conns_.count(conn))
        return;
    queue_.push_back(conn);
    auto it = queue_.end();
    conns_[conn] = --it;
}

void Scheduler::RemoveFromQueue(RemoteConn *conn)
{
    if (!conns_.count(conn))
        return;
    auto it = conns_[conn];
    conns_.erase(conn);
    queue_.erase(it);
}

RemoteConn *Scheduler::Schedule()
{
    if (queue_.empty())
        return NULL;

    auto conn = *queue_.begin();
    RemoveFromQueue(conn);
    return conn;
}
