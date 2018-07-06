#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <new>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <exception>

#include "easy_socket.hpp"

Socket::Socket(): _domain(-1), _ref_count(nullptr), _socket_fd(-1)
{
    memset(&_addrs, 0, sizeof(_addrs)); 
}

Socket::Socket(const int domain, const int type, const int protocol): _domain(-1), _ref_count(nullptr), _socket_fd(-1)
{   
    if (domain != AF_INET && domain != AF_INET6 && domain && AF_UNIX)
        throw ExceptionInfo("no support domain");
    
	memset(&_addrs, 0, sizeof(_addrs));
	_ref_count = new size_t(1);
	
    _socket_fd = socket(domain, type, protocol);  
    if (_socket_fd < 0)
        throw SysError("Socket:can't creat socket: " + get_std_error_str());     
}
                  
Socket::Socket(const Socket &s): _domain(s._domain), _ref_count(s._ref_count), _socket_fd(s._socket_fd), _addrs(s._addrs)
{
	if (s) 
		++*_ref_count;
}

Socket& Socket::operator=(const Socket &s)
{
    if (s)
        ++*s._ref_count; 
    
    _destroy();
    _domain = s._domain; 
	_ref_count = s._ref_count;
	_socket_fd = s._socket_fd;
    _addrs = s._addrs;

    return *this; 
}
            
Socket::Socket(Socket &&s) : _domain(s._domain), _ref_count(s._ref_count), _socket_fd(s._socket_fd), _addrs(s._addrs)
{
    s._ref_count = nullptr;
    s._addrs._addr_in = nullptr;
	s._socket_fd = -1;
}

Socket& Socket::operator=(Socket &&s)
{
    if (this != &s)
    {
        _destroy();      

        _domain = s._domain;        
        _ref_count = s._ref_count;
        _socket_fd = s._socket_fd;
        _addrs = s._addrs;
                
        s._ref_count = nullptr;
        s._addrs._addr_in = nullptr;
        s._socket_fd = -1;  
    }
    
    return *this;
}

Socket::~Socket()
{
    _destroy();
}

void Socket::_destroy()
{
    if (_ref_count && --*_ref_count == 0)
    {
        delete _ref_count;
        _ref_count = nullptr;
        if (_domain == AF_INET && _addrs._addr_in)        
            delete _addrs._addr_in;
        
        else if (_domain == AF_INET6 && _addrs._addr_in6)      
            delete _addrs._addr_in6;
        
        else if ((_domain == AF_UNIX) && _addrs._addr_un)
            delete _addrs._addr_un;

        _addrs._addr_in = nullptr;
        close(_socket_fd);     
    }
}

Socket Socket::accept(int *error_code) const noexcept
{
    Socket new_socket; 
    int new_socket_fd = -1;
    
    if (_domain == AF_INET)
    {
        socklen_t length = sizeof(struct sockaddr_in);
        new_socket._addrs._addr_in = new (struct sockaddr_in);
        new_socket_fd = ::accept(_socket_fd, (struct sockaddr *)new_socket._addrs._addr_in, &length);
    }
    else if (_domain == AF_INET6)
    {
        socklen_t length = sizeof(struct sockaddr_in6);
        new_socket._addrs._addr_in6 = new (struct sockaddr_in6);
        new_socket_fd = ::accept(_socket_fd, (struct sockaddr *)new_socket._addrs._addr_in6, &length);
    }
    else if (_domain == AF_UNIX)
    {
        socklen_t length = sizeof(struct sockaddr_un);
        new_socket._addrs._addr_un = new (struct sockaddr_un);
        memset(new_socket._addrs._addr_un, 0, sizeof(struct sockaddr_un));
        new_socket_fd = ::accept(_socket_fd, (struct sockaddr *)new_socket._addrs._addr_un, &length);         
    }

    if (error_code)
        *error_code = errno;
    
    if (new_socket_fd < 0)
        return new_socket;
     
    new_socket._domain = _domain;
    new_socket._ref_count = new size_t(1);
    new_socket._socket_fd = new_socket_fd;
    
    return new_socket;
}
    
bool Socket::bind(const std::string &addr, const unsigned short int port, int *error_code) noexcept
{
    int flag = -1; 
    
    if (_domain == AF_INET)
    {
        _addrs._addr_in = new (struct sockaddr_in);
        memset(_addrs._addr_in, 0, sizeof(struct sockaddr_in));
        _addrs._addr_in->sin_family = AF_INET;
        _addrs._addr_in->sin_port = htons(port);
        inet_pton(AF_INET, addr.c_str(), &_addrs._addr_in->sin_addr);
        flag = ::bind(_socket_fd, (struct sockaddr *)_addrs._addr_in, sizeof(struct sockaddr_in));
    }
    else if (_domain == AF_INET6)
    {
        _addrs._addr_in6 = new (struct sockaddr_in6);
        memset(_addrs._addr_in6, 0, sizeof(struct sockaddr_in6));
        _addrs._addr_in6->sin6_family = AF_INET6;
        _addrs._addr_in6->sin6_port = htons(port);
        inet_pton(AF_INET6, addr.c_str(), &_addrs._addr_in6->sin6_addr);
        flag = ::bind(_socket_fd, (struct sockaddr *)_addrs._addr_in6, sizeof(struct sockaddr_in6));
    }
    else if (_domain == AF_UNIX)
    {
        _addrs._addr_un = new (struct sockaddr_un);
        memset(_addrs._addr_un, 0, sizeof(struct sockaddr_un));
        _addrs._addr_un->sun_family = AF_UNIX;
        std::copy(addr.begin(), addr.end(), _addrs._addr_un->sun_path);
        flag = ::bind(_socket_fd, (struct sockaddr *)_addrs._addr_un, sizeof(struct sockaddr_un));
    }
    if (error_code)
        *error_code = errno;
   
    return flag == 0; 
}

bool Socket::connect(const std::string &addr, const unsigned short int port, int *error_code) noexcept
{
    int flag = -1; 
    
    if (_domain == AF_INET)
    {
        _addrs._addr_in = new (struct sockaddr_in);
        memset(_addrs._addr_in, 0, sizeof(struct sockaddr_in));
        _addrs._addr_in->sin_family = AF_INET;
        _addrs._addr_in->sin_port = htons(port);
        inet_pton(AF_INET, addr.c_str(), &_addrs._addr_in->sin_addr);
        flag = ::connect(_socket_fd, (struct sockaddr *)_addrs._addr_in, sizeof(struct sockaddr_in));
    }
    else if (_domain == AF_INET6)
    {
        _addrs._addr_in6 = new (struct sockaddr_in6);
        memset(_addrs._addr_in6, 0, sizeof(struct sockaddr_in6));
        _addrs._addr_in6->sin6_family = AF_INET6;
        _addrs._addr_in6->sin6_port = htons(port);
        inet_pton(AF_INET6, addr.c_str(), &_addrs._addr_in6->sin6_addr);
        flag = ::connect(_socket_fd, (struct sockaddr *)_addrs._addr_in6, sizeof(struct sockaddr_in6));
    }
    else if (_domain == AF_UNIX)
    {
        _addrs._addr_un = new (struct sockaddr_un);
        memset(_addrs._addr_un, 0, sizeof(struct sockaddr_un));
        _addrs._addr_un->sun_family = AF_UNIX;
        std::copy(addr.begin(), addr.end(), _addrs._addr_un->sun_path);
        flag = ::connect(_socket_fd, (struct sockaddr *)_addrs._addr_un, sizeof(struct sockaddr_un));
    }
    
    if (error_code)
        *error_code = errno;
   
    return flag == 0; 
}

std::pair<std::string, unsigned short int> Socket::getpeername() const
{
    std::pair<std::string, unsigned short int> addr;
    if (_domain == AF_INET && _addrs._addr_in) 
    {
        addr.first.resize(INET_ADDRSTRLEN, 0);
        inet_ntop(AF_INET, &_addrs._addr_in->sin_addr, &addr.first[0], INET_ADDRSTRLEN);
        addr.second = ntohs(_addrs._addr_in->sin_port);
    }
    else if (_domain == AF_INET6 && _addrs._addr_in6)
    {
        addr.first.resize(INET6_ADDRSTRLEN, 0);
        inet_ntop(AF_INET, &_addrs._addr_in6->sin6_addr, &addr.first[0], INET6_ADDRSTRLEN);
        addr.second = ntohs(_addrs._addr_in6->sin6_port);
    } 
    else if (_domain == AF_UNIX && _addrs._addr_un)
    {
        std::copy(_addrs._addr_un->sun_path, _addrs._addr_un->sun_path + sizeof(_addrs._addr_un->sun_path), std::back_inserter(addr.first));
        addr.second = 0; //meaningless for AF_UNIX
    }
    auto it = std::find(addr.first.begin(), addr.first.end(), 0);
    addr.first.resize(std::distance(addr.first.begin(), it)); 
    return addr;
}
 
bool Socket::listen(const int backlog, int *error_code) const noexcept
{
    int flag = ::listen(_socket_fd, backlog);
    
    if (error_code)
        *error_code = errno;
    
    return flag == 0;
}

int Socket::read(unsigned char *buffer, const size_t max_len, int *error_code) const noexcept
{
    int len = ::read(_socket_fd, buffer, max_len);
    if (error_code)
        *error_code = errno;
    
    return len;
}

std::shared_ptr<unsigned char> Socket::read(const size_t max_len, int &out_len, int *error_code) const noexcept
{
    std::shared_ptr<unsigned char> buffer(new(std::nothrow) unsigned char[max_len], [](unsigned char *p) { delete[] p; });
    if (!buffer)
    {
        if (error_code)
            *error_code = -1;
        return nullptr;
    }
    
    out_len = read(buffer.get(), max_len, error_code);
    if (out_len < 0)
        return nullptr;
    
    return buffer;
}
  
size_t Socket::read(unsigned char *buffer, const size_t max_len) const
{
    int len = ::read(_socket_fd, buffer, max_len);
    
    if (len < 0)
        throw SysError("Socket:read error: " + get_std_error_str());
    
    return len;
}
  
std::shared_ptr<unsigned char> Socket::read(const size_t max_len, size_t &out_len) const 
{
    std::shared_ptr<unsigned char> buffer(new unsigned char[max_len], [](unsigned char *p) { delete[] p; });
    
    if (!buffer)
        throw SysError("Socket::read: can't get memory");
   
    out_len = read(buffer.get(), max_len); 
         
    return buffer;
}

bool Socket::setsockopt(const int level, const int optname, const int option_value, int *error_code) const noexcept
{   
    int flag = ::setsockopt(_socket_fd, level, optname, &option_value, sizeof(int));
    if (error_code)
        *error_code = errno;
    
    return flag == 0;
}

bool Socket::set_sock_blocking(const bool is_block, int *error_code) const noexcept
{
    int flag = ::fcntl(_socket_fd, F_GETFL, 0);
    
    if (flag < 0)
    {
        if (error_code)
            *error_code = errno;
        return false;
    }
               
    if (is_block)
        flag &= ~O_NONBLOCK;
    else
        flag |= O_NONBLOCK;
    
    if (error_code)
        *error_code = errno;
    
    if (::fcntl(_socket_fd, F_SETFL, flag) < 0)       
        return false;
  
    return true;
}

int Socket::write(const unsigned char *buffer, const size_t len, int *error_code) const noexcept
{
    int length = ::write(_socket_fd, buffer, len);
    if (error_code)
        *error_code = errno;
        
    return length;
}

size_t Socket::write(const unsigned char *buffer, const size_t len) const 
{
    int length = ::write(_socket_fd, buffer, len);
    
    if (length < 0)
        throw SysError("Socket:write error: " + get_std_error_str());
    
    return length;               
}

size_t Socket::recvfrom(unsigned char *buffer, const size_t len, std::pair<std::string, unsigned short int> &addr_info, const int flags) const
{
    socklen_t addrlen = sizeof(struct sockaddr_un);
    std::vector<unsigned char> addr(addrlen, 0);

    auto ret = ::recvfrom(_socket_fd, buffer, len, flags, (struct sockaddr *)&addr[0], &addrlen);
    if (ret < 0)
        throw SysError("Socket:recvfrom error: " + get_std_error_str());

    if (_domain == AF_INET && addrlen == sizeof(struct sockaddr_in))
    {
        auto addr_in = (struct sockaddr_in *)&addr[0];
        addr_info.first.resize(INET_ADDRSTRLEN, 0);
        if (!inet_ntop(AF_INET, &addr_in->sin_addr, &addr_info.first[0], INET_ADDRSTRLEN))
            throw ExceptionInfo("Socket:recvfrom invaild ipv4 addr: ");
        
        addr_info.second = ntohs(addr_in->sin_port);
    }
    else if (_domain == AF_INET6 && addrlen == sizeof(struct sockaddr_in6))
    {
        auto addr_in6 = (struct sockaddr_in6 *)&addr[0];
        addr_info.first.resize(INET6_ADDRSTRLEN, 0);
        if (!inet_ntop(AF_INET, &addr_in6->sin6_addr, &addr_info.first[0], INET6_ADDRSTRLEN))
            throw ExceptionInfo("Socket:recvfrom invaild ipv6 addr");
                      
        addr_info.second = ntohs(addr_in6->sin6_port);
    }
    else if (_domain == AF_UNIX)
    {
        auto addr_un = (struct sockaddr_un *)&addr[0];
        std::copy(addr_un->sun_path, addr_un->sun_path + sizeof(addr_un->sun_path), std::back_inserter(addr_info.first));
        addr_info.second = 0; //meaningless for AF_UNIX
    }
    else
        throw ExceptionInfo("Socket:recvfrom unknow addr type");

    auto it = std::find(addr_info.first.begin(), addr_info.first.end(), 0);
    addr_info.first.resize(std::distance(addr_info.first.begin(), it));
    
    return ret;
}

size_t Socket::sendto(const unsigned char *buffer, const size_t len, const std::pair<std::string, unsigned short int> &addr_info,  
                      const int flags) const
{
    int ret = -1;
    if (_domain == AF_INET)
    {   
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(struct sockaddr_in)); 
        addr.sin_family = AF_INET;
        addr.sin_port = htons(addr_info.second);
        if (!inet_pton(AF_INET, addr_info.first.c_str(), &addr.sin_addr))
            throw  ExceptionInfo("invalid network address");
        
        ret = ::sendto(_socket_fd, buffer, len, flags, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    } 
    else if (_domain == AF_INET6)
    {   
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(struct sockaddr_in6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(addr_info.second);
        if(!inet_pton(AF_INET6, addr_info.first.c_str(), &addr6.sin6_addr))
            throw  ExceptionInfo("invalid network address");
        
        ret = ::sendto(_socket_fd, buffer, len, flags, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
    }
    else if (_domain == AF_UNIX)
    {
        struct sockaddr_un addr_un;
        memset(&addr_un, 0, sizeof(struct sockaddr_un));
        addr_un.sun_family = AF_UNIX;
        std::copy(addr_info.first.begin(), addr_info.first.end(), addr_un.sun_path);
        
        ret = ::sendto(_socket_fd, buffer, len, flags, (struct sockaddr *)&addr_un, sizeof(struct sockaddr_un));      
    }        
    
    if (ret < 0)
        throw SysError("Socket:sendto error: " + get_std_error_str());
    
    return ret;
}






