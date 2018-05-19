#ifndef TCPRELAY_HPP
#define TCPRELAY_HPP

#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

#include "json.hpp"
#include "eventloop.hpp"
#include "asyncdns.hpp"
#include "easy_socket.hpp"
#include "cryptor.hpp"

class TCPRelayHandler;

class TCPRelay : public LoopElementBase
{
    friend class TCPRelayHandler;
public:    
    TCPRelay() = default;
    TCPRelay(nlohmann::json &config, const std::shared_ptr<DNSResolver> &dns_resolver, 
             std::function<void(const unsigned short int port, const size_t data_len)> stat_callback = nullptr);
    TCPRelay(const TCPRelay &relay) = delete;
    TCPRelay& operator =(const TCPRelay &relay) = delete;
    ~TCPRelay() { _destroy(); }
    void add_to_loop(const std::shared_ptr<EventLoop> &loop);
    void remove_handler(TCPRelayHandler *handler);
    void handle_periodic() override { _sweep_timeout(); }
    void handle_event(const int socket_fd, const unsigned int events) override;
    void update_activity(TCPRelayHandler *handler, const size_t data_len);

private:
    int _timeout;
    nlohmann::json _config;
    std::shared_ptr<DNSResolver> _dns_resolver;
    std::shared_ptr<EventLoop> _eventloop;
    Socket _server_socket;
    size_t _timeout_offset = 0;
    std::vector<TCPRelayHandler *> _timeouts;
    std::unordered_map<TCPRelayHandler *, size_t> _handler_to_timeouts;
    std::unordered_map<int, std::shared_ptr<TCPRelayHandler>> _fd_to_handlers;
    std::function<void(const unsigned short int port, const size_t data_len)> _stat_callback;
    
    void _destroy();
    void _sweep_timeout();
};

#endif
