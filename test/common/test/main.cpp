#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <assert.h>
#include <algorithm>

#include "easylogging++.hpp"
#include "common.hpp"

INITIALIZE_EASYLOGGINGPP

using namespace std;

template <typename type>
static bool equal_vector(const vector<type> &left, const vector<type> &right)
{
    if (left.size() != right.size())
        return false;
    
    for (size_t i = 0; i < left.size(); i++)
    {
        if (left[i] != right[i])
        {
            return false;
        }
    }
    
    return true;
}

int main()
{
    //start_with
    assert(start_with(" 123456789", " "));
    assert(start_with("abc123456789", "abc"));
    assert(!start_with("bc123456789", "abc"));
    
    //end_with
    assert(end_with("12345678 ", " "));
    assert(end_with("12345678abc", "abc"));
    assert(!end_with("12345678ab", "abc"));
    
    //uint_random
    for (int i = 0; i < 65536 * 2; i++)
    {
        assert(uint_random(8) < 256);
        assert(uint_random(16) < 65536);
    }
    
    //is_ip_str
    assert(is_ip_str("bad_ip_127.0.0.1") == -1);
    assert(is_ip_str("127.0.0.1") == AF_INET);
    assert(is_ip_str("::") == AF_INET6);
    assert(is_ip_str("::8") == AF_INET6);
    assert(is_ip_str("0:0:0:0:0:FFFF:204.152.189.116") == AF_INET6);
    assert(is_ip_str("1:0:0:0:0:0:0:8") == AF_INET6);
    
    //strip
    string str = strip(".1.1.1.1.", ".");
    assert(str == "1.1.1.1");
    str = strip("www.example.com", "cmowz.");
    assert(str == "example");
    
    //split
    vector<string> ret = split("1.1.1.1", ".");
    for (auto &c : ret)
        assert(c == "1");
    
    ret = split("127.0.0.1", "/");
    assert(ret[0] == "127.0.0.1");
    assert(ret.size() == 1);
    
    
    //rsplit
    ret = rsplit("1.1.1.1", ".");
    for (auto &c : ret)
        assert(c == "1");
    
    ret = rsplit("127.0.0.1", "/");
    assert(ret[0] == "127.0.0.1");
    assert(ret.size() == 1);
    
    //onetimeauth_gen  onetimeauth_verify
    vector<unsigned char> data;
    vector<unsigned char> key;
    vector<unsigned char> hash;
    for (int i = 0; i < 255; i++)
    {
        data.push_back(uint_random(8));
        key.push_back(uint_random(8));
    }
    
    onetimeauth_gen(data, key, hash);
    assert(onetimeauth_verify(&hash[0], 10, &data[0], data.size(), key));
    
    //parse_header
    //0x03 0x0e www.google.com 0x00 0x50
    vector<unsigned char> header = {0x03, 0x0e};
    string domain = "www.google.com";
    copy(domain.begin(), domain.end(), back_inserter(header));
    header.push_back(0x00);
    header.push_back(0x50);
    auto p_header = parse_header(header);
    assert(get<0>(p_header) == 3);
    assert(get<1>(p_header) == domain);
    assert(get<2>(p_header) == 80);
    assert(get<3>(p_header) == 18);
    
    //0x01 8.8.8.8 0x00 0x35
    header = {0x01, 0x08, 0x08, 0x08, 0x08, 0x00, 0x35};
    p_header = parse_header(header);
    assert(get<0>(p_header) == 1);
    assert(get<1>(p_header) == "8.8.8.8");
    assert(get<2>(p_header) == 53);
    assert(get<3>(p_header) == 7);
    
    //0x4 2404:6800:4005:805::1011 0x00 0x80
    vector<unsigned char> v6(sizeof(struct in6_addr));
    string ipv6 = "2404:6800:4005:805::1011";    
    inet_pton(AF_INET6, ipv6.c_str(), &v6[0]);
    header = {0x04};
    copy(v6.begin(), v6.end(), back_inserter(header));
    header.push_back(0x00);
    header.push_back(0x50);
    p_header = parse_header(header);
    assert(get<0>(p_header) == 4);
    assert(get<1>(p_header) == ipv6);
    assert(get<2>(p_header) == 80);
    assert(get<3>(p_header) == 19);
    
    //pack_addr
    header.clear();
    vector<unsigned char> temp = {0x01, 0x08, 0x08, 0x08, 0x08};
    string ip = "8.8.8.8";
    pack_addr(ip, header);
    assert(equal_vector(header, temp));
    
    header.clear();
    pack_addr(ipv6, header);
    temp = {0x04};
    copy(v6.begin(), v6.end(), back_inserter(temp));
    assert(equal_vector(header, temp));
    
    header.clear();
    ip = "www.google.com";
    temp = {0x03, 0x0e};
    copy(ip.begin(), ip.end(), back_inserter(temp));
    pack_addr(ip, header);
    assert(equal_vector(header, temp));
    
    //getaddrinfo
    auto addr_udp = getaddrinfo("127.0.0.1", 2333, AF_UNSPEC, SOCK_DGRAM, AI_PASSIVE, IPPROTO_UDP);
    assert(addr_udp.ai_family == AF_INET);
    assert(addr_udp.ai_socktype == SOCK_DGRAM);
    assert(addr_udp.ai_protocol == IPPROTO_UDP);
    assert(addr_udp.ai_addr_str == "127.0.0.1");
    assert(addr_udp.ai_port == 2333);
    auto addr = (struct sockaddr_in *)&addr_udp.ai_addr[0];
    assert(addr->sin_family == AF_INET);
    assert(ntohs(addr->sin_port) == 2333);
    auto fd = socket(addr_udp.ai_family, addr_udp.ai_socktype, addr_udp.ai_protocol);
    assert(fd > 0);    
    assert(bind(fd, (struct sockaddr *)addr, addr_udp.ai_addrlen) == 0);
    close(fd);
  
    
    auto addr_tcp = getaddrinfo("127.0.0.1", 2333, AF_UNSPEC, SOCK_STREAM, AI_PASSIVE, IPPROTO_TCP);
    assert(addr_tcp.ai_family == AF_INET);
    assert(addr_tcp.ai_socktype == SOCK_STREAM);
    assert(addr_tcp.ai_protocol == IPPROTO_TCP);
    assert(addr_tcp.ai_addr_str == "127.0.0.1");
    assert(addr_tcp.ai_port == 2333);
    addr = (struct sockaddr_in *)&addr_tcp.ai_addr[0];
    assert(addr->sin_family == AF_INET);
    assert(ntohs(addr->sin_port) == 2333);
    fd = socket(addr_tcp.ai_family, addr_tcp.ai_socktype, addr_tcp.ai_protocol);
    assert(fd > 0);    
    assert(bind(fd, (struct sockaddr *)addr, addr_tcp.ai_addrlen) == 0);
    close(fd);
    
    auto addrv6 = getaddrinfo("2404:6800:4005:805::1011", 2333, AF_UNSPEC, SOCK_STREAM, AI_PASSIVE, IPPROTO_TCP);
    assert(addrv6.ai_family == AF_INET6);
    assert(addrv6.ai_socktype == SOCK_STREAM);
    assert(addrv6.ai_protocol == IPPROTO_TCP);
    assert(addrv6.ai_addr_str == "2404:6800:4005:805::1011");
    assert(addrv6.ai_port == 2333);
    auto addr_v6 = (struct sockaddr_in6 *)&addrv6.ai_addr[0];
    assert(addr_v6->sin6_family == AF_INET6);
    assert(ntohs(addr_v6->sin6_port) == 2333);
    fd = socket(addrv6.ai_family, addrv6.ai_socktype, addrv6.ai_protocol);
    assert(fd > 0);    
    if (bind(fd, (struct sockaddr *)addr_v6, addrv6.ai_addrlen) < 0)
    {
        cout << get_std_error_str() << endl;
    }
    close(fd);
    
    auto addr_domain = getaddrinfo("www.google.com", 2333, AF_UNSPEC, SOCK_STREAM, AI_PASSIVE, IPPROTO_TCP);
    assert(addr_domain.ai_family == AF_INET);
    assert(addr_domain.ai_socktype == SOCK_STREAM);
    assert(addr_domain.ai_protocol == IPPROTO_TCP);
    assert((is_ip_str(addr_domain.ai_addr_str) == AF_INET || is_ip_str(addr_domain.ai_addr_str) == AF_INET6));
    assert(addr_domain.ai_port == 2333);
    addr_v6 = (struct sockaddr_in6 *)&addr_domain.ai_addr[0];
    assert(addr_v6->sin6_family == AF_INET6 || addr_v6->sin6_family == AF_INET);
    assert(ntohs(addr_v6->sin6_port) == 2333);
    fd = socket(addr_domain.ai_family, addr_domain.ai_socktype, addr_domain.ai_protocol);
    assert(fd > 0);    
    if (bind(fd, (struct sockaddr *)&addr_domain.ai_addr[0], addr_domain.ai_addrlen) < 0)
    {
        cout << get_std_error_str() << endl;
    }
    close(fd);
    
    
    //uint128
    uint128 a(1);
    int b = 1;
    char c = 1;
    assert(a == b);
    assert(a == c);
    b = 2;
    c = 2;
    assert(a != b);
    assert(a != c);
    assert(a < b);
    assert(a < c);
    
    a = 3;
    assert(a > b);
    assert(a > c);
    
    a = 1;
    assert((a >> 1) == (1 >> 1));
    assert((a << 1) == (1 << 1));
    assert((a >>= 1) == (1 >> 1));
    a = 1;
    assert((a <<= 1) == (1 << 1));
    a = 255;
    unsigned long long e = 255;
    assert((a >> 63) == ( e >> 63));
    assert((a << 63) == ( e << 63));
    
    assert((a >>= 63) == (e >> 63));
    a = 1;
    assert((a <<= 63) == (e << 63));
    
    a = 12;
    assert((a & 7) == 4);
    assert((a &= 7) == 4);
    
    a = 12;
    uint128 f(7);
    assert((a & f) == 4);
    assert((a &= f) == 4);
    
    //IPNetwork
    IPNetwork ip_network("127.0.0.0/24,::ff:1/112,::1,192.168.1.1,192.0.2.0");
    assert(ip_network.exist("127.0.0.1"));
    assert(!ip_network.exist("127.0.1.1"));
    assert(ip_network.exist("::ff:ffff"));
    assert(!ip_network.exist("::ffff:1"));
    assert(ip_network.exist("::1"));
    assert(!ip_network.exist("::2'"));
    assert(ip_network.exist("192.168.1.1"));
    assert(!ip_network.exist("192.168.1.2"));
    assert(ip_network.exist("192.0.2.1")); // 192.0.2.0 is treated as 192.0.2.0/23
    assert(ip_network.exist("192.0.3.1")); 
    assert(!ip_network.exist("www.google.com"));

}