#include <errno.h> 
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <algorithm>
#include <iterator>
#include <tuple>
#include <utility>

#include "easylogging++.hpp"
#include "common.hpp"
#include "tcprelay.hpp"


#define TIMEOUTS_CLEAN_SIZE  512

// for each opening port, we have a TCP Relay, including a tcp socket for listening client connection

// for each client connection, we have a TCP Relay Handler to handle the connection

// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:

// as sslocal:
// stage 0 auth METHOD received from local, reply with selection message
// stage 1 addr received from local, query DNS for remote 
// stage 2 UDP assoc 
// stage 3 DNS resolved, connect to remote 
// stage 4 still connecting, more data from local received
// stage 5 remote connected, piping local and remote

// as ssserver:
// stage 0 just jump to stage 1
// stage 1 addr received from local, query DNS for remote
// stage 3 DNS resolved, connect to remote
// stage 4 still connecting, more data from local received
// stage 5 remote connected, piping local and remote

#define STAGE_INIT  0
#define STAGE_ADDR  1
#define STAGE_UDP_ASSOC  2
#define STAGE_DNS  3
#define STAGE_CONNECTING  4
#define STAGE_STREAM  5
#define STAGE_DESTROYED  -1

// for each handler, we have 2 stream directions:
//    upstream:    from client to server direction
//                 read local and write to remote
//
//    downstream:  from server to client direction
//                 read remote and write to local

#define STREAM_UP  0
#define STREAM_DOWN  1

// for each stream, it's waiting for reading, or writing, or both
#define WAIT_STATUS_INIT  0
#define WAIT_STATUS_READING  1
#define WAIT_STATUS_WRITING  2
#define WAIT_STATUS_READWRITING  (WAIT_STATUS_READING | WAIT_STATUS_WRITING)

#define BUF_SIZE  (32 * 1024)

#define ADDRTYPE_AUTH  0x10

class TCPRelayHandler : public DNSHandle
{
public:
    TCPRelayHandler() = default;
    TCPRelayHandler(TCPRelay *server, const Socket &local_sock, nlohmann::json &config);
    TCPRelayHandler(const TCPRelayHandler &handler) = delete;
    TCPRelayHandler& operator=(const TCPRelayHandler &handler) = delete;
    ~TCPRelayHandler() { _destroy(); }
    void handle_dns_resolved(const std::string &hostname, const std::string &ip, const std::string &error);
    void handle_event(const int socket_fd, const unsigned int events);
    std::pair<int, int> get_sockets() { return std::make_pair(_local_sock.get_socket(), _remote_sock.get_socket()); }
    time_t last_activity = 0;
    std::pair<std::string, unsigned short int> _client_address;
    std::pair<std::string, unsigned short int> _remote_address;
    
private:
    void _update_stream(const int stream, const int status);
    bool _write_to_sock(const std::vector<unsigned char> &data, const Socket &sock);
    void _handle_stage_addr(const std::vector<unsigned char> &data);
    Socket _create_remote_socket(const std::string &ip);    
    void _on_local_read();
    void _on_remote_read();
    void _on_local_write();
    void _on_remote_write();
    void _destroy();

private:
    TCPRelay *_server = nullptr;
    Socket _local_sock;
    Socket _remote_sock;
    int _stage = 0;

    std::vector<unsigned char> _data_to_write_to_local;
    std::vector<unsigned char> _data_to_write_to_remote;
    int _upstream_status = 1;
    int _downstream_status = 0;
    
    IPNetwork _forbidden_iplist; 
    Cryptor _cryptor; 
};

TCPRelayHandler::TCPRelayHandler(TCPRelay *server, const Socket &local_sock, nlohmann::json &config): 
                                 _forbidden_iplist(config["forbidden_ip"].get<std::string>()),  _cryptor(config["password"], config["method"])
{
    _server = server;
    _local_sock = local_sock;
    _client_address = local_sock.getpeername();
    _local_sock.set_sock_blocking(false);
    _local_sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);               
    server->_eventloop->add(local_sock.get_socket(), EPOLLIN | EPOLLRDHUP, server);                                                  
    server->update_activity(this, 0);
}

void TCPRelayHandler::_update_stream(const int stream, const int status)
{
    // update a stream to a new waiting status

    // check if status is changed
    // only update if dirty
    bool dirty = false;
    if (stream == STREAM_DOWN)
    {
        if (_downstream_status != status)
        {
            _downstream_status = status;
            dirty = true;
        }
    }
    else if (stream == STREAM_UP)
    {
        if (_upstream_status != status)
        {
            _upstream_status = status;
            dirty = true;
        }
    }
    if (!dirty)
        return;

    if (_local_sock)
    {
        unsigned int event = EPOLLERR | EPOLLRDHUP;
        
        if (_downstream_status & WAIT_STATUS_WRITING)
            event |= EPOLLOUT;
            
        if (_upstream_status & WAIT_STATUS_READING)
            event |= EPOLLIN;
            
        _server->_eventloop->modify(_local_sock.get_socket(), event);
    }
        
    if (_remote_sock)
    {
        unsigned int event = EPOLLERR | EPOLLRDHUP;
        
        if (_downstream_status & WAIT_STATUS_READING)
            event |= EPOLLIN;
            
        if (_upstream_status & WAIT_STATUS_WRITING)
            event |= EPOLLOUT;
            
        _server->_eventloop->modify(_remote_sock.get_socket(), event);
    }
}

bool TCPRelayHandler::_write_to_sock(const std::vector<unsigned char> &data, const Socket &sock) 
{
    // write data to sock
    // if only some of the data are written, put remaining in the buffer
    // and update the stream to wait for writing
    if (data.empty() || !sock)
        return false;

    bool uncomplete = false;

    auto len = data.size();
    size_t write_len = 0;
    try
    {
        write_len = sock.write(data);
        if (write_len < len)
            uncomplete = true;
    }
    catch (SysError &e)
    {
        if (errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK)        
            uncomplete = true;
        else
        {
            LOG(ERROR) << e.what();
            _destroy();
            return false;
        }
    }
    
    if (uncomplete)
    {
        if (sock == _local_sock)
        {
            std::copy(data.begin() + write_len, data.end(), std::back_inserter(_data_to_write_to_local));
            _update_stream(STREAM_DOWN, WAIT_STATUS_WRITING);
        }            
        else if (sock == _remote_sock)
        {
            std::copy(data.begin() + write_len, data.end(), std::back_inserter(_data_to_write_to_remote));
            _update_stream(STREAM_UP, WAIT_STATUS_WRITING);
        }             
        else
            LOG(ERROR) << "write_all_to_sock:unknown socket";
    }
    else
    {
        if (sock == _local_sock)
            _update_stream(STREAM_DOWN, WAIT_STATUS_READING);            
        else if (sock == _remote_sock)
            _update_stream(STREAM_UP, WAIT_STATUS_READING);             
        else
            LOG(ERROR) << "write_all_to_sock:unknown socket";
    }

    return true;
}

void TCPRelayHandler::_handle_stage_addr(const std::vector<unsigned char> &data)
{
    auto header_result = parse_header(data);
    if (std::get<1>(header_result).empty())
        throw ExceptionInfo("can not parse header");
        
    auto addrtype = std::get<0>(header_result);
    auto remote_addr = std::get<1>(header_result);
    auto remote_port = std::get<2>(header_result);
    auto header_length = std::get<3>(header_result);
    
    el::Logger* el_log = el::Loggers::getLogger("default");
    el_log->info("connecting %v:%v from %v:%v", remote_addr, remote_port, _client_address.first, _client_address.second);
  
    if (addrtype & ADDRTYPE_AUTH)
    {
        LOG(WARNING) << "client one time auth is required, but should using aead encryption method instead like xchacha20-ietf-poly1305, ignore the connection.";
        return;
    }
    _remote_address = std::make_pair(remote_addr, remote_port);
    
    // pause reading
    _update_stream(STREAM_UP, WAIT_STATUS_WRITING);
    _stage = STAGE_DNS;
    std::copy(data.begin() + header_length, data.end(), std::back_inserter(_data_to_write_to_remote));
    _server->_dns_resolver->resolve(remote_addr, this);
}

Socket TCPRelayHandler::_create_remote_socket(const std::string &ip)
{       
    if(_forbidden_iplist.exist(ip))
        throw ExceptionInfo("IP " + ip + " is in forbidden list, reject");
            
    Socket remote_sock = Socket(is_ip_str(ip), SOCK_STREAM, 0);
    auto hd = _server->_fd_to_handlers.find(_local_sock.get_socket());
    _server->_fd_to_handlers[remote_sock.get_socket()] = hd->second;
    remote_sock.set_sock_blocking(false);
    remote_sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
    return remote_sock;
}

void TCPRelayHandler::handle_dns_resolved(const std::string &hostname, const std::string &ip, const std::string &error)
{
    if (!error.empty())
    {
        el::Logger* el_log = el::Loggers::getLogger("default");
        el_log->debug("%v when handling connection from %v:%v", error, _client_address.first, _client_address.second);
        _destroy();
        return;
    }
    if (hostname.empty() || ip.empty())
    {
        LOG(DEBUG) << "hostname empty or ip empty";
        _destroy();
        return;
    }

    el::Logger* el_log = el::Loggers::getLogger("default");
    el_log->info("connected %v(%v):%v from %v:%v", _remote_address.first, ip, _remote_address.second, _client_address.first, _client_address.second);
    
    _remote_address.first = ip;
    _remote_sock = _create_remote_socket(ip);
    _server->_eventloop->add(_remote_sock.get_socket(), EPOLLOUT | EPOLLRDHUP, _server);
    
    try
    {
        _remote_sock.connect(_remote_address.first, _remote_address.second);
    }
    catch (SysError &e)
    {
        if (errno == EINPROGRESS)
            ;
        else
        {
            LOG(ERROR) << e.what();
            _destroy();
            return;
        }
    }
    
    _stage = STAGE_CONNECTING; 
    _update_stream(STREAM_UP, WAIT_STATUS_READWRITING);
    _update_stream(STREAM_DOWN, WAIT_STATUS_READING);   
}


void TCPRelayHandler::_on_local_read()
{
    // handle all local read events and dispatch them to methods for each stage
    if (!_local_sock)
        return;

    std::vector<unsigned char> data;
    int buf_size = BUF_SIZE;
    size_t ret_len = 0;

    try
    {
        ret_len = _local_sock.read(data, buf_size);
    }
    catch (SysError &e)
    {
        if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else
        {
            LOG(ERROR) << e.what();
            _destroy();
            return;
        }
    }

    if (ret_len == 0)
    {
        _destroy();
        return;
    }

    _server->update_activity(this, ret_len);

    std::vector<unsigned char> decrypt_data;
    try
    {
        _cryptor.decrypt(&data[0], ret_len, decrypt_data);
    }
    catch (std::exception &e)
    {
        LOG(ERROR) << e.what();
        _destroy();
        return;
    }
    
    if (decrypt_data.empty())                       
        return;

    if (_stage == STAGE_STREAM)   
        _write_to_sock(decrypt_data, _remote_sock);
        
    else if (_stage == STAGE_CONNECTING)
        std::copy(decrypt_data.begin(), decrypt_data.end(), std::back_inserter(_data_to_write_to_remote));

    else if (_stage == STAGE_INIT)
        _handle_stage_addr(decrypt_data);
}

void TCPRelayHandler::_on_remote_read()
{
    std::vector<unsigned char> data;
    int buf_size = BUF_SIZE;
    size_t ret_len = 0;

    try
    {
        ret_len = _remote_sock.read(data, buf_size);
    }
    catch (SysError &e)
    {
        if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
    }

    if (ret_len == 0)
    {
        _destroy();
        return;
    }
    
    _server->update_activity(this, ret_len);
    try
    {
        std::vector<unsigned char> encrypt_data;
        _cryptor.encrypt(&data[0], ret_len, encrypt_data);
        _write_to_sock(encrypt_data, _local_sock);
    }
    catch (std::exception &e)
    {
        LOG(ERROR) << e.what();
        _destroy(); 
    }
}

void TCPRelayHandler::_on_local_write()
{
    // handle local writable event
    if (!_data_to_write_to_local.empty())
    {
        auto data = std::move(_data_to_write_to_local);
        _data_to_write_to_local.clear();
        _write_to_sock(data, _local_sock);
    }        
    else
        _update_stream(STREAM_DOWN, WAIT_STATUS_READING);
}

void TCPRelayHandler::_on_remote_write()
{
    // handle remote writable event
    _stage = STAGE_STREAM;
    if (!_data_to_write_to_remote.empty())
    {
        auto data = std::move(_data_to_write_to_remote);
        _data_to_write_to_remote.clear();
        _write_to_sock(data, _remote_sock);
    }
    else
        _update_stream(STREAM_UP, WAIT_STATUS_READING);
}

void TCPRelayHandler::handle_event(const int socket_fd, const unsigned int events)
{
    // handle all events in this handler and dispatch them to methods
    // order is important

    if (_stage == STAGE_DESTROYED)
    {
        LOG(DEBUG) << "ignore handle_event: destroyed";
        return;
    }
    try
    {
        if (socket_fd == _remote_sock.get_socket())
        {
            if (events & EPOLLERR)
            {
                LOG(DEBUG) << "got remote error";
                _destroy();
                return;
            }

            if (events & (EPOLLIN | EPOLLHUP))
            {
                _on_remote_read();
                if (_stage == STAGE_DESTROYED) 
                    return;
            }

            if (events & EPOLLRDHUP)
            {
                LOG(DEBUG) << "close by remote";
                _destroy();
                return;
            }

            if (events & EPOLLOUT)
                _on_remote_write();
        }
        else if (socket_fd == _local_sock.get_socket())
        {                         
            if (events & EPOLLERR)
            {
                LOG(DEBUG) << "got local error";
                _destroy();
                return;
            }

            if (events & (EPOLLIN | EPOLLHUP))
            {
                _on_local_read();
                if (_stage == STAGE_DESTROYED)
                    return;
            }

            if (events & EPOLLRDHUP)
            {
                LOG(DEBUG) << "closed by locla";
                _destroy();
                return;
            }

            if (events & EPOLLOUT)
                _on_local_write();
        }
        else
        {
            el::Logger* el_log = el::Loggers::getLogger("default"); 
            el_log->warn("unknown socket: %v, locla socket: %v, remote socket: %v", socket_fd, _local_sock.get_socket(), _remote_sock.get_socket()); 
            LOG(DEBUG) << "destroying unknown socket";
            _server->_eventloop->remove(socket_fd);
            close(socket_fd);
            auto it = _server->_fd_to_handlers.find(socket_fd);
            if (it != _server->_fd_to_handlers.end())
                _server->_fd_to_handlers.erase(it);
            
            _destroy();
        }
    }
    catch (std::exception &e) //catch all the exceptions
    {
        LOG(DEBUG) << e.what();
        _destroy(); 
    }
}

void TCPRelayHandler::_destroy()
{
    if (_stage == STAGE_DESTROYED)
        return;
    
    _stage = STAGE_DESTROYED; 
    _server->_dns_resolver->remove_callback(this);
    _server->remove_handler(this);
    
    if (!_remote_address.first.empty())
    {
        el::Logger* el_log = el::Loggers::getLogger("default");
        el_log->debug("destroy: %v:%v", _remote_address.first, _remote_address.second);
    }
    if (_local_sock)
    {
        LOG(DEBUG) << "destroying local";
        try
        {
            _server->_eventloop->remove(_local_sock.get_socket());
        }
        atch (std::exception &e)
        {
            LOG(ERROR) << e.what();
        }
        
        auto it_local = _server->_fd_to_handlers.find(_local_sock.get_socket());
        if (it_local != _server->_fd_to_handlers.end())
            _server->_fd_to_handlers.erase(it_local);
    } 
    if (_remote_sock)
    {
        LOG(DEBUG) << "destroying remote";
        try
        {
            _server->_eventloop->remove(_remote_sock.get_socket());
        }
        atch (std::exception &e)
        {
            LOG(ERROR) << e.what();
        }
        
        auto it_remote = _server->_fd_to_handlers.find(_remote_sock.get_socket());
        if (it_remote != _server->_fd_to_handlers.end())
            _server->_fd_to_handlers.erase(it_remote);
    }

}

TCPRelay::TCPRelay(nlohmann::json &config, const std::shared_ptr<DNSResolver> &dns_resolver, 
                   std::function<void(const unsigned short int port, const size_t data_len)> stat_callback)
{
    _config = config;
    _dns_resolver = dns_resolver;
    std::string listen_addr = _config["server"];
    _server_socket = Socket(is_ip_str(listen_addr), SOCK_STREAM, 0);
    _server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
    _server_socket.bind(listen_addr, _config["server_port"]);
    _server_socket.set_sock_blocking(false);
    _timeout = _config["timeout"];
    _stat_callback = stat_callback;
    if (_config["fast_open"])
    {       
        if(!_server_socket.setsockopt(IPPROTO_TCP, 23, 5, nullptr))
        {
            LOG(WARNING) << "warning: fast open is not available";
            _config["fast_open"] = false;;
        }
    }
    _server_socket.listen(1024);                            
}

void TCPRelay::add_to_loop(const std::shared_ptr<EventLoop> &loop)
{
    if (_eventloop)
        throw ExceptionInfo("already add to loop");

    _eventloop = loop;

    _eventloop->add(_server_socket.get_socket(), EPOLLIN, this); 
    _eventloop->add_periodic(this); 
}

void TCPRelay::remove_handler(TCPRelayHandler *handler)
{
    auto it = _handler_to_timeouts.find(handler);
    if (it != _handler_to_timeouts.end())
    {
        // delete is O(n), so we just set it to None
        _timeouts[it->second] = nullptr;
        _handler_to_timeouts.erase(it);
    }
}

#define TIMEOUT_PRECISION 10

void TCPRelay::update_activity(TCPRelayHandler *handler, const size_t data_len)
{
    if (data_len && _stat_callback)
        _stat_callback(_config["server_port"], data_len);
    
    auto now = time(nullptr);
    if (now - handler->last_activity < TIMEOUT_PRECISION) // thus we can lower timeout modification frequency
        return;

    handler->last_activity = now;
    
    auto it = _handler_to_timeouts.find(handler);
    if (it != _handler_to_timeouts.end())
    {
        // delete is O(n), so we just set it to None
        _timeouts[it->second] = nullptr;
    }

    auto length = _timeouts.size();
    _timeouts.push_back(handler);
    _handler_to_timeouts[handler] = length;
}

void TCPRelay::_sweep_timeout()
{
    // tornado's timeout memory management is more flexible than we need
    // we just need a sorted last_activity queue and it's faster than heapq
    // in fact we can do O(1) insertion/remove so we invent our own
    if (!_timeouts.empty())
    {
        LOG(DEBUG) << "sweeping timeouts";
        auto now = time(nullptr);
        auto length = _timeouts.size();
        auto pos = _timeout_offset;
        while (pos < length)
        {
            auto handler = _timeouts[pos];
            if (handler)
            {
                if (now - handler->last_activity < _timeout)
                    break;
                else
                {
                    if (!handler->_remote_address.first.empty())
                        LOG(WARNING) << "timed out: " <<  handler->_remote_address.first << ":" << handler->_remote_address.second;
                    else
                        LOG(WARNING) << "timed out";                  
                    
                    //destory the handler
                    auto socksets = handler->get_sockets();

                    //handler local socket _handler_to_timeouts
                    auto it_local = _fd_to_handlers.find(socksets.first);
                    if (it_local != _fd_to_handlers.end())                    
                        _fd_to_handlers.erase(it_local);
                    
                    //handler remote socket
                    auto it_remote = _fd_to_handlers.find(socksets.second);
                    if (it_remote != _fd_to_handlers.end())
                        _fd_to_handlers.erase(it_remote);
                    
                    _timeouts[pos] = nullptr;
                    pos += 1;
                }
            }
            else
            {
                pos += 1;
            }
        }
        // clean up the timeout queue when it gets larger than half of the queue
        if (pos > TIMEOUTS_CLEAN_SIZE && pos > length >> 1)
        {    
            std::copy(_timeouts.begin() + pos, _timeouts.end(), _timeouts.begin());
            _timeouts.resize(_timeouts.size() - pos);

            for (auto it = _handler_to_timeouts.begin(); it != _handler_to_timeouts.end(); it++)
            {
               it->second -= pos;
            }
            pos = 0;
        }
        
        _timeout_offset = pos;
    }
}

void TCPRelay::handle_event(const int socket_fd, const unsigned int events)
{ 
    if (socket_fd == _server_socket.get_socket())
    { 
        if (events & EPOLLERR)
        {
            try
            {
                _eventloop->remove(_server_socket.get_socket());
                close(_server_socket.get_socket());
                std::string listen_addr = _config["server"];
                _server_socket = Socket(is_ip_str(listen_addr), SOCK_STREAM, 0);
                _server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
                _server_socket.bind(listen_addr, _config["server_port"]);
                _server_socket.set_sock_blocking(false);
                if (_config["fast_open"])
                {       
                    if(!_server_socket.setsockopt(IPPROTO_TCP, 23, 5, nullptr))
                    {
                        LOG(WARNING) << "warning: fast open is not available";
                        _config["fast_open"] = false;;
                    }
                }
                _server_socket.listen(1024);
            }
            catch (std::exception &e)
            {
                LOG(ERROR) << "server socket error :" << e.what();
                exit(1);
            }
            
            return;
        }
        
        try
        {
            LOG(DEBUG) << "accept";
            auto socket = _server_socket.accept();
            auto handler = std::make_shared<TCPRelayHandler>(this, socket, _config);
            _fd_to_handlers[socket.get_socket()] = handler;
        }                  
        catch (SysError &e)
        {
            if (errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK)
                return;
            else
                LOG(ERROR) << "server socket error :" << e.what();
        }
        catch (std::exception &e)
        {
            LOG(ERROR) << "server socket error :" << e.what();
        }
        
    }
    else
    {
        auto it = _fd_to_handlers.find(socket_fd);
        if (it != _fd_to_handlers.end())                                     
            it->second->handle_event(socket_fd, events);    
        else
            LOG(WARNING) << "poll removed fd";
    }
}

void TCPRelay::_destroy()
{
    if (_eventloop)
    {
        _eventloop->remove_periodic(this);
        _eventloop->remove(_server_socket.get_socket());
    } 
}
