#ifndef EVENTLOOP_HPP
#define EVENTLOOP_HPP

#include <unistd.h>
#include <sys/epoll.h>

#include <memory>
#include <unordered_map>
#include <vector>

#define MaxEvents 2000

/*

EPOLLIN  //read
EPOLLOUT //write 
EPOLLRDHUP //Stream socket peer closed connection, or shut down writing half of connection.

EPOLLPRI //There is urgent data available for read(2) operations.
 
EPOLLERR //Error condition happened on the associated file descriptor. epoll_wait(2) will always wait for this event; 
         //it is not necessary to set it in events.

EPOLLHUP //Hang up happened on the associated file descriptor. epoll_wait(2) will always wait for this event; 
        //it is not necessary to set it in events.
EPOLLET //Sets the Edge Triggered behavior for the associated file descriptor. The default behavior for epoll is Level Triggered. 
*/
                       
class LoopElementBase
{
public:
    LoopElementBase() = default;
    LoopElementBase(const LoopElementBase &leb) = delete;
    LoopElementBase& operator =(const LoopElementBase &leb) = delete;

    virtual void handle_event(const int socket_fd, const unsigned int events) = 0;
    virtual void handle_periodic() = 0;
    virtual ~LoopElementBase() = default;
};


class EventLoop
{ 
public:
    EventLoop();
    ~EventLoop() { _destroy(); }
    EventLoop(const EventLoop &el) = delete;
    EventLoop& operator =(const EventLoop &el) = delete;
    void poll(const int timeout = 0);
    void add(const int fd, const unsigned int mode, LoopElementBase *base);
    void remove(const int fd);
    void add_periodic(LoopElementBase *periodic)
    {
        _periodic_callbacks.push_back(periodic);
    }

    void remove_periodic(LoopElementBase *callback);
    void modify(const int fd, const unsigned int mode);
    void run();
    
private:
    time_t _last_time;
    
    int _epoll_fd = -1;
    int _event_ctivity = -1;
    struct epoll_event _events[MaxEvents];
    std::vector<LoopElementBase *> _periodic_callbacks; 
    std::unordered_map<int, LoopElementBase *> _fd_map;

    void _destroy();
};


#endif