#ifndef EASY_SOCKET_HPP
#define EASY_SOCKET_HPP

#include <strings.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <string>
#include <vector>
#include <memory>
#include <utility> 

#include "common.hpp"
    
class Socket
{
public:
    Socket(); 
    Socket(const int domain, const int type, const int protocol);
    Socket(const Socket &s);
    Socket &operator=(const Socket &s);         
    Socket(Socket &&s);
    Socket &operator=(Socket &&s);
    ~Socket();
    
    Socket(const int fd) : _socket_fd(fd) {} //temporarily for STL find
    bool operator==(const Socket &s) const { return _socket_fd != -1 && s._socket_fd != -1 && _socket_fd == s._socket_fd; }
    bool operator!=(const Socket &s) const { return !(*this == s); }
    explicit operator bool() const { return _socket_fd == -1 ? false : true; }
    
public:
    Socket accept(int *error_code) const noexcept;
    Socket accept() const
    {
        Socket socket = accept(nullptr);
        if (!socket)
            throw SysError("Socket::accept:can't accept new socket: " + get_std_error_str());
        
        return socket;
    }
    
    bool bind(const std::string &addr, const unsigned short int port, int *error_code) noexcept;
    void bind(const std::string &addr, const unsigned short int port)
    {
        if (!bind(addr, port, nullptr))
            throw SysError("Socket:bind error: " + get_std_error_str());
    }
    
    bool connect(const std::string &addr, const unsigned short int port, int *error_code) noexcept;
    void connect(const std::string &addr, const unsigned short int port)
    {
        if (!connect(addr, port, nullptr))
            throw SysError("Socket:connect error: " + get_std_error_str());
    }
    
    const int get_socket() const { return _socket_fd; }
    std::pair<std::string, unsigned short int> getpeername() const; 
    

    bool listen(const int backlog, int *error_code) const noexcept;
    void listen(const int backlog) const
    {
        if (!listen(backlog, nullptr))
            throw SysError("Socket:listen error: " + get_std_error_str());
    }
    
    int read(unsigned char *buffer, const size_t max_len, int *error_code) const noexcept;
    int read(std::string &buffer, const size_t max_len, int *error_code) const noexcept
    {
        buffer.resize(max_len);
        return read((unsigned char *)&buffer[0], max_len, error_code);
    }
    int read(std::vector<unsigned char> &buffer, const size_t max_len, int *error_code) const noexcept
    {
        buffer.resize(max_len);
        return read(&buffer[0], max_len, error_code);
    }

    std::shared_ptr<unsigned char> read(const size_t max_len, int &out_len, int *error_code) const noexcept;
    
    size_t read(unsigned char *buffer, const size_t max_len) const;
    size_t read(std::string &buffer, const size_t max_len) const
    {
        buffer.resize(max_len);
        return read((unsigned char *)&buffer[0], max_len);
    }

    size_t read(std::vector<unsigned char> &buffer, const size_t max_len) const
    {
        buffer.resize(max_len);
        return read(&buffer[0], max_len);
    }
    std::shared_ptr<unsigned char> read(const size_t max_len, size_t &out_len) const;
    
    bool setsockopt(const int level, const int optname, const int option_value, int *error_code) const noexcept;
    void setsockopt(const int level, const int optname, const int option_value) const
    {
        if (!setsockopt(level, optname, option_value, nullptr))
            throw SysError("Socket:setsockopt error: " + get_std_error_str());
    }
    
    bool set_sock_blocking(const bool is_block, int *error_code) const noexcept;
    void set_sock_blocking(const bool is_block) const 
    {  
        if (!set_sock_blocking(is_block, nullptr))      
            throw SysError("Socket:set_socke_blocking error: " + get_std_error_str());
    }
    
    int write(const unsigned char *buffer, const size_t len, int *error_code) const noexcept;
    int write(const std::string &buffer, int *error_code) const noexcept
    {
        return write((unsigned char *)buffer.c_str(), buffer.size(), error_code);
    }

    int write(const std::vector<unsigned char> &buffer, int *error_code) const noexcept
    {
        return write(&buffer[0], buffer.size(), error_code);
    }
    
    size_t write(const unsigned char *buffer, const size_t len) const;
    size_t write(const std::string &buffer) const
    {   
        return write((unsigned char*)buffer.c_str(), buffer.size());
    } 

    size_t write(const std::vector<unsigned char> &buffer) const
    {
        return write(&buffer[0], buffer.size());
    }

    size_t recvfrom(unsigned char *buffer, const size_t len, std::pair<std::string, unsigned short int> &addr_info, 
                    const int flags = 0) const;
                    
    size_t recvfrom(std::vector<unsigned char> &buffer, const size_t len, std::pair<std::string, unsigned short int> &addr_info, 
                                const int flags = 0) const
    {
        buffer.resize(len);
        return recvfrom(&buffer[0], len, addr_info, flags);
    }

                    
    size_t sendto(const unsigned char *buffer, const size_t len, const std::pair<std::string, unsigned short int> &addr_info, 
                         const int flags = 0) const;
                         
    size_t sendto(const std::vector<unsigned char> &buffer, const std::pair<std::string, unsigned short int> &addr_info, 
                             const int flags = 0) const
    {
        return sendto(&buffer[0], buffer.size(), addr_info, flags);
    }
    
private:
    int _domain;
    size_t *_ref_count;
    int _socket_fd;
    union
    {
        struct sockaddr_in *_addr_in;
        struct sockaddr_in6 *_addr_in6;
        struct sockaddr_un *_addr_un;
    } _addrs;

    void _destroy();
};


#endif
