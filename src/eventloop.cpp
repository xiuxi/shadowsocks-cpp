#include <time.h>
#include <errno.h> 

#include "easylogging++.hpp"
#include "common.hpp"
#include "eventloop.hpp"

static const int TIMEOUT_PRECISION = 10000; //10 s = 10000 ms

EventLoop::EventLoop()
{ 
    _last_time = time(nullptr);
    _epoll_fd = epoll_create(MaxEvents);
    if (_epoll_fd < 0)
    {
        LOG(ERROR) << "epoll_create error: " << get_std_error_str(); 
        exit(1);
    }
}

void EventLoop::poll(const int timeout)
{
    _event_ctivity = epoll_wait(_epoll_fd, _events, MaxEvents, timeout); 
    if (_event_ctivity < 0)
    {
        throw SysError("epoll error: " + get_std_error_str());
    }          
}

void EventLoop::add(const int fd, const unsigned int mode, LoopElementBase *base)
{    
    if (_fd_map.find(fd) != _fd_map.end())
    {
        throw ExceptionInfo("the fd already exists ");
    }

    _fd_map[fd] = base;
    struct epoll_event ept;
    ept.events = mode;
    ept.data.fd = fd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, fd, &ept) < 0)
    {
        throw SysError("epoll_ctl add error: " + get_std_error_str());
    }
}

void EventLoop::remove(const int fd)
{
    auto it = _fd_map.find(fd); 
    if (it == _fd_map.end())
    {
        throw ExceptionInfo("the fd don't exists");
    }
    _fd_map.erase(it);

    if (epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) < 0) //see the EPOLL_CTL_DEL BUG: https://linux.die.net/man/2/epoll_ctl
    {
        throw SysError("epoll_ctl delete error: " + get_std_error_str());
    }     
}

void EventLoop::remove_periodic(LoopElementBase *callback)
{
    for (auto it = _periodic_callbacks.begin(); it != _periodic_callbacks.end(); it++)
    {
        if (*it == callback)
        {
            _periodic_callbacks.erase(it);
            break;
        }
    }   
}

void EventLoop::modify(const int fd, const unsigned int mode)
{
    struct epoll_event ept;
    ept.events = mode;
    ept.data.fd = fd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_MOD, fd, &ept) < 0)
    {
        throw SysError("epoll_ctl modify error: " + get_std_error_str());
    }
}


void EventLoop::run()
{
    while (true)
    {
        bool asap = false;
        try
        {
            poll(TIMEOUT_PRECISION);
        }
        catch (SysError &e)
        {
            if (errno == EINTR)
            {
                // EINTR: Happens when received a signal
                // handles them as soon as possible
                asap = true;
            }
            else
            {
                LOG(ERROR) << e.what(); 
                exit(1);
            }
        }
         
        for (int i = 0; i < _event_ctivity; i++)
        {
            auto it = _fd_map.find(_events[i].data.fd); 
            if (it != _fd_map.end())
            {
                try
                {
                    it->second->handle_event(_events[i].data.fd, _events[i].events);
                }
                catch (SysError &e) 
                {          
                    if (errno == EINTR)
                    {
                        // EPIPE: Happens when the client closes the connection
                        // handles them as soon as possible
                        asap = true;
                    }
                    else
                    {
                        LOG(ERROR) << e.what(); 
                        exit(1);
                    }                    
                } 
            }
        }
        auto now = time(nullptr);
        if (asap || now - _last_time >= TIMEOUT_PRECISION / 1000)
        {
            for (auto &c : _periodic_callbacks)
                 c->handle_periodic();
  
            _last_time = now;
        }
    }
}


void EventLoop::_destroy()
{
    if (_epoll_fd > 0)
    {
        if (close(_epoll_fd) < 0)
        {
            LOG(ERROR) << "close epoll fd error: " << get_std_error_str();
        }

        _epoll_fd = -1;
    }
}