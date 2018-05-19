#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h> 
#include <unistd.h>

#include <string>
#include <exception>
#include <vector>
#include <memory>

#include "easylogging++.hpp"

#include "common.hpp"
#include "tcprelay.hpp"
#include "udprelay.hpp"
#include "daemon.hpp"
#include "server.hpp"
#include "manager.hpp"

static std::vector<int> children;

static void handler(int signum)
{
    for(auto &pid : children)
    {
        kill(pid, signum);
        waitpid(pid, nullptr, 0);
    }
    exit(0);
}

void run_server(nlohmann::json &config)
{
    if (!config["port_password"].empty())
    {
        if (!config["password"].get<std::string>().empty())
            LOG(WARNING) << "warning: port_password should not be used with server_port and password. server_port and password will be ignored";
    }
    else
    {
        auto &server_port = config["server_port"];
        for (auto &c : server_port)
            config["port_password"][std::to_string(c.get<int>())] = config["password"].get<std::string>();                                                         
    }

    if (!config["manager_address"].get<std::string>().empty())
    {
        LOG(INFO) << "entering manager mode";
        Manager manager(config);
        manager.run(); 
        return;
    }

    std::vector<std::shared_ptr<TCPRelay>> tcp_servers; 
    std::vector<std::shared_ptr<UDPRelay>> udp_servers; 
    std::shared_ptr<DNSResolver> dns_resolver;
    std::vector<std::string> v_dns;
    if (!config["dns_server"].is_null())
    {  
        auto &dns = config["dns_server"];
        for (auto &c : dns)
            v_dns.push_back(c);
        dns_resolver = std::make_shared<DNSResolver>(v_dns, (bool)config["prefer_ipv6"]);
    }
    else
        dns_resolver = std::make_shared<DNSResolver>(v_dns, (bool)config["prefer_ipv6"]);

    auto port_password = config["port_password"];
    config.erase("port_password"); 
    
    for (auto beg = port_password.begin(); beg != port_password.end(); beg++)
    {
        auto one_config = config;
        one_config["server_port"] = std::stoi(beg.key()); 
        one_config["password"] = beg.value(); 
        
        LOG(INFO) << "starting server at " << config["server"].get<std::string>() << ":" << beg.key();
        try
        { 
            tcp_servers.push_back(std::make_shared<TCPRelay>(one_config, dns_resolver)); 
            udp_servers.push_back(std::make_shared<UDPRelay>(one_config, dns_resolver));
        }
        catch (std::exception &e)
        {
            LOG(ERROR) << e.what();
            exit(1);
        } 
    } 

    auto run_server = [&]()
    {
        auto sig_handler = [](int signum) { exit(0); }; //simply exit
        
        struct sigaction act_sigpipe;
        struct sigaction act_sig;
        memset(&act_sigpipe, 0, sizeof(act_sigpipe));
        memset(&act_sig, 0, sizeof(act_sig));
        act_sigpipe.sa_handler = SIG_IGN;        
        act_sig.sa_handler = sig_handler;
        
        if (sigaction(SIGPIPE, &act_sigpipe, nullptr) < 0)
        {
            LOG(ERROR) << "sigaction error: " << get_std_error_str();
            exit(1);
        }
        if (sigaction(SIGQUIT, &act_sig, nullptr) < 0) 
        {
            LOG(ERROR) << "sigaction error: " << get_std_error_str();
            exit(1);
        }
        if (sigaction(SIGTERM, &act_sig, nullptr) < 0)
        {
            LOG(ERROR) << "sigaction error: " << get_std_error_str();
            exit(1);
        }
        if (sigaction(SIGINT, &act_sig, nullptr) < 0)
        {
            LOG(ERROR) << "sigaction error: " << get_std_error_str();
            exit(1);
        }

        try
        {
            auto loop = std::make_shared<EventLoop>();
            dns_resolver->add_to_loop(loop);
            for (auto beg = tcp_servers.begin(); beg != tcp_servers.end(); beg++)
                (*beg)->add_to_loop(loop);
            for  (auto beg = udp_servers.begin(); beg != udp_servers.end(); beg++)
                (*beg)->add_to_loop(loop);

            set_user(config["user"]);
            loop->run();
        }
        catch (std::exception &e) 
        {          
            LOG(ERROR) << e.what(); 
            exit(1);
        }
    };

    if (config["workers"].get<int>() > 1)
    {
        bool is_child = false;
        for (int i = 0; i < config["workers"].get<int>(); i++)
        {
            int r = fork();
            if (r == 0)
            {
                LOG(INFO) << "worker started";
                is_child = true;
                run_server();
                break; //need to break in the child 
            }
            else 
                children.push_back(r);
        }
        if (!is_child) //parent
        {
            struct sigaction act_sig;
            memset(&act_sig, 0, sizeof(act_sig));
            act_sig.sa_handler = handler;
            if (sigaction(SIGTERM, &act_sig, nullptr) < 0) 
            {
                LOG(ERROR) << "sigaction error: " << get_std_error_str();
                exit(1);
            }
            if (sigaction(SIGQUIT, &act_sig, nullptr) < 0) 
            {
                LOG(ERROR) << "sigaction error: " << get_std_error_str();
                exit(1);
            }
            if (sigaction(SIGINT, &act_sig, nullptr) < 0) 
            {
                LOG(ERROR) << "sigaction error: " << get_std_error_str();
                exit(1);
            }

            tcp_servers.clear();
            udp_servers.clear();
            dns_resolver.reset();

            //parent wait for child exit
            for (auto &child : children) 
                waitpid(child, nullptr, 0);
        }
    }
    else
        run_server();
}