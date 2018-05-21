#ifndef UDPRELAY_HPP
#define UDPRELAY_HPP

#include <string>
#include <sstream>
#include <functional>
#include <unordered_set>

#include "json.hpp"

#include "eventloop.hpp"
#include "asyncdns.hpp"
#include "easy_socket.hpp"
#include "lru_cache.hpp"

struct Socket_hash
{
   std::size_t operator()(const Socket &s) const 
   {
   		static std::hash<int> hash_int;
   		return hash_int(s.get_socket());
   }
};

struct pair_str_int_hash
{
   std::size_t operator()(const std::pair<std::string, unsigned short int> &str_int) const 
   {
   		std::hash<std::string> hash_str;
        std::hash<int> hash_int;
   		return hash_str(str_int.first) ^ hash_int(str_int.second);
   }
};

struct AddrInfo_hash
{
   std::size_t operator()(const AddrInfo &addr) const 
   {
   		std::hash<std::string> hash_stsr;
        std::stringstream sstream_addr;
        sstream_addr << addr.ai_family << addr.ai_socktype << addr.ai_protocol << addr.ai_addr_str << addr.ai_port;
   		return hash_stsr(sstream_addr.str());
   }
};

class UDPRelay : public LoopElementBase
{
public:
    UDPRelay() = default;
    UDPRelay(nlohmann::json &config, const std::shared_ptr<DNSResolver> &dns_resolver, 
             std::function<void(const unsigned short int port, const size_t data_len)> stat_callback = nullptr);
    ~UDPRelay() { _destory(); }
    void handle_periodic() override;
    void handle_event(const int socket_fd, const unsigned int events) override;
    void add_to_loop(std::shared_ptr<EventLoop> &loop);
    void close_client(const Socket &client);
    
private:
    void _handle_server();
    void _handle_client(const Socket &sock);
    void _destory();
    
private:
    Socket _server_socket;    
    std::shared_ptr<DNSResolver> _dns_resolver;
    std::string _password;
    std::string _method;
    unsigned short int _listen_port;
    std::shared_ptr<EventLoop> _eventloop;
    IPNetwork _forbidden_iplist;
    std::function<void(const unsigned short int port, const size_t data_len)> _stat_callback;
    
    std::unordered_set<Socket, Socket_hash> _sockets;
    LRUCache<std::string, Socket, Socket_hash> _sockets_cache;
    LRUCache<int, std::pair<std::string, unsigned short int>, pair_str_int_hash> _relay_fd_to_server_recv_addr;
    LRUCache<std::string, AddrInfo, AddrInfo_hash> _dns_cache;
};



#endif