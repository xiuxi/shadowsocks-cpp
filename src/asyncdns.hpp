#ifndef ASYNCDNS_HPP
#define ASYNCDNS_HPP

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>

#include "eventloop.hpp"
#include "easy_socket.hpp"
#include "lru_cache.hpp"

class DNSHandle
{
public:
    DNSHandle() = default;
    virtual void handle_dns_resolved(const std::string &hostname, const std::string &ip, const std::string &error) = 0;
    virtual~DNSHandle() {}
};

class DNSResolver : public LoopElementBase
{
public:
    DNSResolver(): DNSResolver(std::vector<std::string>(), false) {}
    DNSResolver(const std::vector<std::string> &server_list, bool prefer_ipv6);
    DNSResolver(const DNSResolver &dns_rsl) = delete;
    DNSResolver& operator =(const DNSResolver &dns_rsl) = delete;
    ~DNSResolver() { _destory(); };
    void handle_event(const int socket_fd, const unsigned int events) override;
    void handle_periodic() override { _cache.sweep();}
    void add_to_loop(std::shared_ptr<EventLoop> &loop);
    void remove_callback(DNSHandle *hd);
    void resolve(const std::string &hostname, DNSHandle *hd);
    
private:
    void _parse_resolv();
    void _parse_hosts();
    void _call_callback(const std::string &hostname, const std::string &ip = "", const std::string &error = "");
    void _handle_data(const std::vector<unsigned char> &data);
    void _send_req(const std::string &hostname, const int qtype);
    void _destory();
    
private:
    std::shared_ptr<EventLoop> _loop;
    std::unordered_map<std::string, std::string> _hosts;
    std::unordered_map<std::string, int> _hostname_status;
    std::unordered_map<std::string, std::vector<DNSHandle *>> _hostname_to_vector_hd; 
    std::unordered_map<DNSHandle *, std::string> _hd_to_hostname;
    LRUCache<std::string, std::string> _cache;
    Socket _sock;

    std::vector<int> _QTYPES;
    std::vector<std::string> _servers;
};


#endif