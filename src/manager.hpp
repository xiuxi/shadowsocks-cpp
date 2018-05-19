#ifndef MANAGER_HPP
#define MANAGER_HPP

#include <memory>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <utility>

#include "json.hpp"
#include "common.hpp"
#include "eventloop.hpp"
#include "udprelay.hpp"
#include "tcprelay.hpp"

class Manager : public LoopElementBase
{
public:
    Manager() = default;
    ~Manager() = default;
    Manager(const Manager &m) = delete;
    Manager& operator=(const Manager &m) = delete;
    
    Manager(nlohmann::json &config) : _config(config)
    {
        _eventloop = std::make_shared<EventLoop>();
        _dns_resolver = std::make_shared<DNSResolver>();
        _dns_resolver->add_to_loop(_eventloop);
        
        try
        {
            std::string manager_address = _config["manager_address"];
            int family = -1;
            std::vector<std::string> addr;
            if (manager_address.find(':') != std::string::npos)
            {
                addr = rsplit(manager_address, ":", 1);
                auto addr_info = getaddrinfo(addr[0], std::stoi(addr[1]), 0, 0, 0, 0);
                if (!addr_info.empty())
                    family = addr_info.ai_family;
                else
                {
                    LOG(ERROR) << "invalid address: " <<  manager_address;
                    exit(1);
                }
            }
            else
            {
                addr.push_back(manager_address);
                addr.push_back("0");
                family = AF_UNIX;
            }
            
            _control_socket = Socket(family, SOCK_DGRAM, 0);
            _control_socket.bind(addr[0], std::stoi(addr[1]));
            _control_socket.set_sock_blocking(false);
        }
        catch (std::exception &e)
        {
            LOG(ERROR) << e.what();
            LOG(ERROR) << "can not bind to manager address";
            exit(1);
        }
        _eventloop->add(_control_socket.get_socket(), EPOLLIN | EPOLLRDHUP, this);
        _eventloop->add_periodic(this);

        auto port_password = _config["port_password"];
        _config.erase("port_password");
        for (auto beg = port_password.begin(); beg != port_password.end(); beg++)
        {
            auto one_config = _config;
            one_config["server_port"] = beg.key();
            one_config["password"] = beg.value();
            _add_port(one_config);
        }    
    }
            
    void handle_event(const int socket_fd, const unsigned int events) override
    {
        static const int buf_size = 1506;

        if (socket_fd == _control_socket.get_socket() && events == EPOLLIN)
        {
            std::vector<unsigned char> data;
            size_t read_len = _control_socket.recvfrom(data, buf_size, _control_client_addr);
            data.resize(read_len);
            auto parsed = _parse_command(data);
            if (!parsed.first.empty())
            {
                auto one_config = _config;
                if (!parsed.second.is_null())
                {
                    // let the command override the configuration file
                    for (auto beg = parsed.second.begin(); beg != parsed.second.end(); beg++)
                        one_config[beg.key()] = beg.value();
                }
                
                if (one_config["server_port"].is_null())
                {
                    LOG(ERROR) << "can not find server_port in config";
                }
                else
                {
                    std::string command(parsed.first.begin(), parsed.first.end());
                    if (command == "add")
                    {
                        _add_port(one_config);
                        _send_control_data("ok");
                    }
                    else if (command == "remove")
                    {
                        _remove_port(one_config);
                        _send_control_data("ok");
                    }
                    else if (command == "ping")
                    {
                        _send_control_data("pong");
                    }
                    else
                    {
                        LOG(ERROR) << "unknown command " << command;
                    }
                }
            }
        }
    }
    
    void handle_periodic() override
    {
        static const int STAT_SEND_LIMIT = 50;
        std::unordered_map<std::string, size_t> r;
        int i = 0;
        
        for (auto beg = _statistics.begin(); beg != _statistics.end(); beg++)
        {
            int port = beg->first;
            r[std::to_string(port)] = beg->second;
            i += 1;
            // split the data into segments that fit in UDP packets
            if (i >= STAT_SEND_LIMIT)
            {
                _send_data(r);
                r.clear();
                i = 0;
            }
        }
        
        if (r.size() > 0)// use compact JSON format (without space)     
            _send_data(r);
        
        _statistics.clear();
    }

    void stat_callback(const unsigned short int port, const size_t data_len) 
    { 
        _statistics[port] += data_len; 
    }
    
    void run() 
    { 
        _eventloop->run(); 
    }
        
private:

    void _send_data(std::unordered_map<std::string, size_t> &data_dict)
    {
        nlohmann::json config(data_dict);
        std::string js_str = "stat: ";
        js_str += config.dump();
        _send_control_data(js_str);
    }
            
    void _add_port(nlohmann::json &config)
    {
        unsigned short int port = config["server_port"];
        auto servers_it = _relays.find(port);
        
        if (servers_it != _relays.end())
        {
            LOG(ERROR) << "server already exists at " << config["password"].get<std::string>() << ":" << port;
            return;
        }

        LOG(INFO) << "adding server at " << config["password"].get<std::string>() << ":" << port;
        auto tcp = std::make_shared<TCPRelay>(config, _dns_resolver, 
                                              std::bind(&Manager::stat_callback, this, std::placeholders::_1, std::placeholders::_2));
        auto udp = std::make_shared<UDPRelay>(config, _dns_resolver, 
                                              std::bind(&Manager::stat_callback, this, std::placeholders::_1, std::placeholders::_2));
        tcp->add_to_loop(_eventloop);
        udp->add_to_loop(_eventloop);
        _relays[port] = std::make_pair(tcp, udp);
    }

    void _remove_port(nlohmann::json &config)
    {
        unsigned short int port = config["server_port"];
        auto it = _relays.find(port); 
        if (it != _relays.end())
        {
            LOG(INFO) << "removing server at " << config["server"].get<std::string>() << ":" << port;
            _relays.erase(it);
        }
        else
            LOG(ERROR) << "server not exist at " << config["server"].get<std::string>() << ":" << port;
    }

    std::pair<std::vector<unsigned char>, nlohmann::json> _parse_command(const std::vector<unsigned char> &data)
    {
        // commands:
        // add: {"server_port": 8000, "password": "foobar"}
        // remove: {"server_port": 8000"}
        auto it = std::find(data.begin(), data.end(), ':');
        nlohmann::json config;

        if (it == data.end())
            return std::make_pair(data, config);

        std::vector<unsigned char> command(data.begin(), it);        
        try
        {
            nlohmann::json config = nlohmann::json::parse(++it, data.end());
            return std::make_pair(command, config);
        }
        catch(nlohmann::json::parse_error &e)
        {
            LOG(ERROR) << e.what();
            command.clear();
            return std::make_pair(command, config);
        }
    }
    
    void _send_control_data(const unsigned char *data, const size_t data_len)
    {
        if (_control_client_addr.first.empty())
            return;

        try
        {
            _control_socket.sendto(data, data_len, _control_client_addr);
        }
        catch (SysError &e)
        {
            if (errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK)
                return;
            else
                LOG(ERROR) << e.what();
        }
    }
    
    void _send_control_data(const std::vector<unsigned char> &data)
    {
        _send_control_data(&data[0], data.size());
    }
    
    void _send_control_data(const std::string &data)
    {
        _send_control_data((unsigned char *)&data[0], data.size());
    }
    
private:
    nlohmann::json _config;
    Socket _control_socket;
    std::unordered_map<unsigned short int, std::pair<std::shared_ptr<TCPRelay>, std::shared_ptr<UDPRelay>>> _relays;
    std::shared_ptr<EventLoop> _eventloop;
    std::shared_ptr<DNSResolver> _dns_resolver;
    std::unordered_map<unsigned short int, size_t> _statistics;
    std::pair<std::string, unsigned short int> _control_client_addr;
};

#endif