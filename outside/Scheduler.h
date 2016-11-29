#ifndef _OUTSIDE_SCHEDULER_H_
#define _OUTSIDE_SCHEDULER_H_
#include <unordered_map>
#include <list>
#include <unordered_map>

class RemoteConn;

class Scheduler {
    std::list<RemoteConn *> queue_;
    typedef std::list<RemoteConn *>::iterator QueueIter;
    std::unordered_map<RemoteConn *, QueueIter> conns_;
        
public:
    void AddToQueue(RemoteConn *conn);
    void RemoveFromQueue(RemoteConn *conn);
    RemoteConn *Schedule();
};

#endif

