#include <netdb.h>

#include <algorithm>
#include <iterator>
#include <tuple>
#include <utility>
#include <sstream>

#include "easylogging++.hpp"
#include "cryptor.hpp"
#include "common.hpp"
#include "udprelay.hpp"

#define BUF_SIZE  65536

#define ADDRTYPE_AUTH  0x10

/*
# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+
*/

static std::string client_key(const std::pair<std::string, unsigned short int> &source_addr, const int server_af)
{
    //notice this is server af, not dest af
    std::stringstream sstr("");
    sstr << source_addr.first << ":" << source_addr.second << ":" << server_af;
    return sstr.str();
}

UDPRelay::UDPRelay(nlohmann::json &config, const std::shared_ptr<DNSResolver> &dns_resolver, 
                   std::function<void(const unsigned short int port, const size_t data_len)> stat_callback): 
                   _dns_resolver(dns_resolver), _forbidden_iplist(config["forbidden_ip"].get<std::string>())
{
    _password = config["password"];
    _method = config["method"];
    _listen_port = config["server_port"];
    _stat_callback = stat_callback;
    
    _sockets_cache = LRUCache<std::string, Socket, Socket_hash>(double(config["timeout"]), 
                                                                std::bind(&UDPRelay::close_client, this, std::placeholders::_1));
    _relay_fd_to_server_recv_addr = LRUCache<int, std::pair<std::string, unsigned short int>, pair_str_int_hash>(double(config["timeout"]));
    _dns_cache = LRUCache<std::string, AddrInfo, AddrInfo_hash>(300);

    _server_socket = Socket(is_ip_str(config["server"]), SOCK_DGRAM, 0);
    _server_socket.bind(config["server"], config["server_port"]);
    _server_socket.set_sock_blocking(false);
}

void UDPRelay::close_client(const Socket &client)
{
    _sockets.erase(client);
    _eventloop->remove(client.get_socket());
}

void UDPRelay::_handle_server()
{
    el::Logger* el_log = el::Loggers::getLogger("default");
    size_t ret_len;
    std::vector<unsigned char> data;
    std::pair<std::string, unsigned short int> recv_addr;
    std::vector<unsigned char> de_data;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    try
    {
        ret_len = _server_socket.recvfrom(data, BUF_SIZE, recv_addr);
    }
    catch (std::exception &e)
    {
        if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else
        {
            LOG(ERROR) << e.what();
            return;
        }
    }
    
    if (ret_len == 0)
        LOG(DEBUG) << "UDP handle_server: data is empty";

    if (_stat_callback)
        _stat_callback(_listen_port, ret_len);
            
    // decrypt data
    try
    {
        decrypt_all(_password, _method, &data[0], ret_len, de_data, key, iv);
    }
    catch (std::exception &e)
    {
        LOG(DEBUG) << "UDP handle_server: decrypt data failed";
        return;
    }
    if (de_data.empty())
    {
        LOG(DEBUG) << "UDP handle_server: data is empty after decrypt";
        return;
    }

    auto header_result = parse_header(de_data);
    if (std::get<1>(header_result).empty()) 
        return;

    auto addrtype = std::get<0>(header_result);
    auto dest_addr = std::get<1>(header_result);
    auto dest_port = std::get<2>(header_result);
    auto header_length = std::get<3>(header_result);
    el_log->info("udp data to %v:%v from %v:%v", dest_addr, dest_port, recv_addr.first, recv_addr.second);
    
    if (addrtype & ADDRTYPE_AUTH)
    {
        LOG(WARNING) << "client one time auth is required, but should using aead encryption method instead like xchacha20-ietf-poly1305, ignore the data.";
        return;
    }
    
    AddrInfo addrs;
    addrs = _dns_cache.get(dest_addr, addrs);
    if (addrs.empty())
    {
        addrs = getaddrinfo(dest_addr.c_str(), dest_port, AF_UNSPEC, SOCK_DGRAM, AI_PASSIVE, IPPROTO_UDP);
        if (addrs.empty())
            return;
        else
            _dns_cache.set(dest_addr, addrs);
    }
    
    std::string str_key = client_key(recv_addr, addrs.ai_family);
    Socket relay;
    relay = _sockets_cache.get(str_key, relay);
    if (!relay)
    {
        //TODO async getaddrinfo
        if (_forbidden_iplist.exist(addrs.ai_addr_str))
        {
            el_log->debug("IP %v is in forbidden list, drop", addrs.ai_addr_str);
            return;
        }
        relay = Socket(addrs.ai_family, addrs.ai_socktype, addrs.ai_protocol);
        relay.set_sock_blocking(false);
        _sockets_cache.set(str_key, relay);
        _relay_fd_to_server_recv_addr.set(relay.get_socket(), recv_addr);

        _sockets.insert(relay);
        _eventloop->add(relay.get_socket(), EPOLLIN, this);
    }

    if (de_data.size() == header_length)
        return;
    
    auto ret = sendto(relay.get_socket(), &de_data[0] + header_length, de_data.size() - header_length, 0, (struct sockaddr *)&addrs.ai_addr[0], addrs.ai_addrlen);
    if (ret < 0)
    {
        if (errno == EINPROGRESS || errno == EAGAIN)
            ;
        else
            LOG(ERROR) << get_std_error_str();
    }
}

void UDPRelay::_handle_client(const Socket &sock)
{
    el::Logger* el_log = el::Loggers::getLogger("default");
    size_t ret_len;
    std::vector<unsigned char> data;
    std::pair<std::string, unsigned short int> recv_addr;
    std::vector<unsigned char> de_data;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    try
    {
        ret_len = sock.recvfrom(data, BUF_SIZE, recv_addr);
    }
    catch (std::exception &e)
    {
        if (errno == ETIMEDOUT || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else
        {
            LOG(ERROR) << e.what();
            return;
        }
    }
    
    if (ret_len == 0)
    {
        LOG(DEBUG) << ("UDP handle_client: data is empty");
        return;
    }
   
    if (_stat_callback)
        _stat_callback(_listen_port, ret_len);
    
    if (recv_addr.first.size() > 255)
        return;

    //pack data
    std::vector<unsigned char> to_en_data;
    pack_addr(recv_addr.first, to_en_data);
    auto port = htons(recv_addr.second);
    to_en_data.push_back(port & 0xff); 
    to_en_data.push_back(port >> 8 & 0xff); 
    std::copy(data.begin(), data.begin() + ret_len, std::back_inserter(to_en_data));

    std::vector<unsigned char> response;
    try
    {
        encrypt_all(_password, _method, to_en_data, response);
    }
    catch (std::exception &e)
    {
        el_log->debug("UDP handle_client: encrypt data failed");
        return;
    }
    if (response.empty())
        return;

    std::pair<std::string, unsigned short int> client_addr;
    client_addr = _relay_fd_to_server_recv_addr.get(sock.get_socket(), client_addr);
    if (!client_addr.first.empty())
    {
        el_log->debug("send udp response to %v:%v", recv_addr.first, recv_addr.second);
        try
        {
            _server_socket.sendto(response, client_addr);
        }
        catch (std::exception &e)
        {
            if (errno == EINPROGRESS || errno == EAGAIN)
                ;
            else
                LOG(DEBUG) << e.what();
        }
    }
    else
    {
        // this packet is from somewhere else we know
        // simply drop that packet
        ;
    }
}

void UDPRelay::add_to_loop(std::shared_ptr<EventLoop> &loop)
{
    if (_eventloop)
        throw ExceptionInfo("already add to loop");

    _eventloop = loop;

    _eventloop->add(_server_socket.get_socket(), EPOLLIN | EPOLLERR, this);
    _eventloop->add_periodic(this);
}

void UDPRelay::handle_event(const int socket_fd, const unsigned int events) 
{
    if (socket_fd == _server_socket.get_socket())
    {
        if (events & EPOLLERR)
            LOG(ERROR) << "UDP server_socket err";
        _handle_server();
    }
    else 
    {
        auto s = Socket(socket_fd);
        auto it = _sockets.find(s);
        if (it != _sockets.end())
        {
            if (events & EPOLLERR)
                LOG(ERROR) << "UDP client_socket err";

            _handle_client(*it);
        }
    }
}

void UDPRelay::handle_periodic() 
{
    _sockets_cache.sweep();
    _relay_fd_to_server_recv_addr.sweep();
    _dns_cache.sweep();
}

void UDPRelay::_destory()
{
    if (_eventloop)
    {
        _eventloop->remove_periodic(this);
        _eventloop->remove(_server_socket.get_socket());

        for(auto it = _sockets.begin(); it != _sockets.end(); it++)
        {
            _eventloop->remove(it->get_socket());
        }
    }
}
