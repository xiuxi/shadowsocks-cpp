#include <iostream>
#include <string>
#include <exception>

#include "easylogging++.hpp"
#include "eventloop.hpp"
#include "asyncdns.hpp"

INITIALIZE_EASYLOGGINGPP


class hd : public DNSHandle
{
public:
    void handle_dns_resolved(const std::string &hostname, const std::string &ip, const std::string &error) override
    {
        std::cout << hostname << " " << ip << " " << error << std::endl;
    }
};

int main(int argc, char *argv[])
{
    init_easylog();
    std::vector<std::string> server_list;
    DNSResolver dns_resolver(server_list, false);
    auto loop = std::make_shared<EventLoop>();
    dns_resolver.add_to_loop(loop);
    
    hd cb;
    try
    {
        dns_resolver.resolve("www.baidu.com", &cb);  
        dns_resolver.resolve("google.com", &cb);
        dns_resolver.resolve("example.com", &cb);
        dns_resolver.resolve("ipv6.google.com", &cb);
        dns_resolver.resolve("www.facebook.com", &cb);
        dns_resolver.resolve("ns2.google.com", &cb);
        dns_resolver.resolve("invalid.@!#$%^&$@.hostname", &cb);
        dns_resolver.resolve("tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolong.hostname", 
                             &cb);
        dns_resolver.resolve("tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolong.hostname", 
                             &cb);
        loop->run();
    }
    catch(std:: exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    return 0; 
}

