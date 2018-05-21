#include <execinfo.h>
#include <stdlib.h>
#include <cxxabi.h>
#include <errno.h> 
#include <time.h>
#include <math.h> 
#include <unistd.h>

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sys/un.h>

#include <random> 
#include <sstream>
#include <typeinfo>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "easylogging++.hpp"
#include "common.hpp"

#define COM_BIG_ENDIAN    0 
#define COM_LITTLE_ENDIAN 1

#define ONETIMEAUTH_BYTES 10
#define ONETIMEAUTH_CHUNK_BYTES 12
#define ONETIMEAUTH_CHUNK_DATA_LEN 2

#define ADDRTYPE_IPV4  0x01
#define ADDRTYPE_IPV6  0x04
#define ADDRTYPE_HOST  0x03
#define ADDRTYPE_AUTH  0x10
#define ADDRTYPE_MASK  0xF


static int byte_order()  
{  
    int num = 1;  
    char *p = (char *)&num;      
    if(*p == 1)  
        return COM_LITTLE_ENDIAN;          
    else  
        return COM_BIG_ENDIAN;                
}  

struct Uint64
{  
    unsigned int u32_h;  
    unsigned int u32_l;  
};  

union ConvertUint64
{  
    unsigned long long u64;  
    Uint64 st64;  
};

/*
static unsigned long long htonll(const unsigned long long host_ll)
{  
    if (byte_order() == COM_LITTLE_ENDIAN)
    {
        ConvertUint64 in, out;  

        in.u64 = host_ll;  
        out.st64.u32_h = htonl(in.st64.u32_l);  
        out.st64.u32_l = htonl(in.st64.u32_h);  
        return out.u64;
    }
    else  
        return host_ll;   
}*/

static unsigned long long ntohll(const unsigned long long net_ll)  
{
    if (byte_order() == COM_LITTLE_ENDIAN)
    {
        ConvertUint64 in, out;  

        in.u64 = net_ll;  
        out.st64.u32_h = ntohl(in.st64.u32_l);  
        out.st64.u32_l = ntohl(in.st64.u32_h);  
        return out.u64;
    }
    else
        return net_ll;
}

void init_easylog()
{
    el::Configurations defaultConf;
    defaultConf.setToDefault();
    
    defaultConf.setGlobally(el::ConfigurationType::Enabled, "true");
    defaultConf.setGlobally(el::ConfigurationType::ToFile, "false");
    defaultConf.setGlobally(el::ConfigurationType::ToStandardOutput, "true");
    defaultConf.setGlobally(el::ConfigurationType::Format, "%datetime{%Y-%M-%d %H:%m:%s}    %level: %msg");
    defaultConf.setGlobally(el::ConfigurationType::PerformanceTracking, "false");
    defaultConf.setGlobally(el::ConfigurationType::MaxLogFileSize, "2097152");
    defaultConf.setGlobally(el::ConfigurationType::SubsecondPrecision, "6");
    defaultConf.setGlobally(el::ConfigurationType::LogFlushThreshold, "100"); 
    defaultConf.set(el::Level::Fatal, el::ConfigurationType::Enabled, "false");
    defaultConf.set(el::Level::Verbose, el::ConfigurationType::Enabled, "false");
    
    el::Loggers::reconfigureLogger("default", defaultConf);   
}

std::string get_std_error_str()
{
    std::string msg;
    if (errno != 0) 
        msg = strerror(errno);
    
    return msg;
}

std::string get_opensll_error_str()
{
    std::string msg;
    unsigned long error_code = ERR_peek_last_error();
    if (error_code != 0)
        msg = ERR_reason_error_string(error_code);
 
    return msg;
}

bool start_with(const std::string &str, const std::string &chars)
{
    return str.substr(0, chars.size()) == chars;
}

bool end_with(const std::string &str, const std::string &chars)
{
    if (chars.size() > str.size())
        return false;
    return str.substr(str.size() - chars.size(), str.size()) == chars;
}

unsigned int uint_random(const int size)
{
	static std::default_random_engine e(time(nullptr));
    static std::uniform_int_distribution<unsigned int> u(0, exp2(size * 8) - 1);	
	return u(e);
}

int is_ip_str(const std::string &address)
{
    unsigned char buf[sizeof(struct in6_addr)];
    
    if (inet_pton(AF_INET, address.c_str(), buf))
        return AF_INET;
    else if (inet_pton(AF_INET6, address.c_str(), buf))    
        return AF_INET6;
    else    
        return -1;
}

std::string strip(const std::string &str, const std::string &chars)
{
    int beg = 0;
    int end = 0;
    for (auto &c : str)
    {
        if(chars.find(c) != std::string::npos)
           beg++;
        else
            break;
    }
    for (auto rit = str.rbegin(); rit != str.rend(); rit++)
    {
        if(chars.find(*rit) != std::string::npos)
           end++;
        else
            break;   
    }
    
    return  str.substr(beg, str.size() - beg - end);
}

std::vector<std::string> split(const std::string &str, const std::string &sep, int max_split)
{
    std::vector<std::string> vec_str;
    size_t beg = 0;
    size_t pos = 0;
    int counts = 0;
    for (; pos < str.size(); pos++)
    {
        if(sep.find(str[pos]) != std::string::npos)
        {
            if (max_split < 0 || counts++ < max_split)
            {
                vec_str.push_back(str.substr(beg, pos - beg));
                beg = pos + 1;                
            }
            else
            {
            	pos = str.size();
                break;
			}
        }
    }
    vec_str.push_back(str.substr(beg, pos - beg));

    return vec_str;
}

std::vector<std::string> rsplit(const std::string &str, const std::string &sep, int max_split)
{
    std::vector<std::string> vec_str;
    size_t end = str.size();
    int pos = str.size() - 1;
    int counts = 0;
    for (; pos >= 0; pos--)
    {
        if(sep.find(str[pos]) != std::string::npos)
        {
            if (max_split < 0 || counts++ < max_split)
            {
                vec_str.push_back(str.substr(pos + 1, end - pos));
                end = pos - 1;                
            }
            else
            {
            	pos = -1;
                break;
			}
        }
    }
    vec_str.push_back(str.substr(pos + 1, end - pos));

    return std::vector<std::string>(vec_str.rbegin(), vec_str.rend());
}

/*
*    -------+----------+----------+
*    | ATYP | DST.ADDR | DST.PORT |
*    +------+----------+----------+
*    |  1   | Variable |    2     |
*    -------+----------+----------+
*/

std::tuple<unsigned char, std::string, unsigned short int, unsigned int> parse_header(const std::vector<unsigned char> &data)
{                       
    unsigned char addrtype = data[0];
    std::string dest_addr;   
    unsigned short int dest_port;
    unsigned int header_length = 0;
    if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_IPV4)
    {
        if (data.size() >= 7)
        {
            struct in_addr addr;
            addr.s_addr = copy_vector_to_value<unsigned int>(data, 1);
            dest_addr.resize(INET_ADDRSTRLEN, 0);
            
            if (!inet_ntop(AF_INET, &addr, (char *)&dest_addr[0], INET_ADDRSTRLEN))
                dest_addr.clear();

            auto it = std::find(dest_addr.begin(), dest_addr.end(), 0);
            dest_addr.resize(std::distance(dest_addr.begin(), it));

            dest_port = ntohs(copy_vector_to_value<unsigned short int>(data, 5));
            header_length = 7;
        }
        else
            LOG(WARNING) << "header is too short";
    }
    else if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_HOST)
    {
        if (data.size() > 2)
        {
            unsigned int addrlen = data[1];
            if (data.size() >= 4 + addrlen)
            {
                dest_addr.resize(addrlen);
                std::copy(data.begin() + 2, data.begin() + 2 + addrlen, dest_addr.begin());
                dest_port = ntohs(copy_vector_to_value<unsigned short int>(data, 2 + addrlen));
                header_length = 4 + addrlen;
            }
            else
                LOG(WARNING) << "header is too short";
        }
        else
            LOG(WARNING) << "header is too short";
    }
    else if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_IPV6)
    {
        if (data.size() >= 19)
        {
            struct in6_addr addr;
            std::copy(data.begin() + 1, data.begin() + 17, addr.s6_addr);
            dest_addr.resize(INET6_ADDRSTRLEN, 0);
            if (!inet_ntop(AF_INET6, &addr, (char *)&dest_addr[0], INET6_ADDRSTRLEN))
                dest_addr.clear();

            auto it = std::find(dest_addr.begin(), dest_addr.end(), 0);
            dest_addr.resize(std::distance(dest_addr.begin(), it));
            
            dest_port = ntohs(copy_vector_to_value<unsigned short int>(data, 17));
            header_length = 19;
        }
        else
            LOG(WARNING) << "header is too short";
    }
    else
        LOG(WARNING) << "unsupported addrtype " << addrtype << "maybe wrong password or encryption method";

    return std::make_tuple(addrtype, dest_addr, dest_port, header_length);
}

void pack_addr(std::string &address, std::vector<unsigned char> &addr)
{
    unsigned char buf[sizeof(struct in6_addr)];
    
    if (inet_pton(AF_INET, address.c_str(), buf))
    {
        addr.push_back(0x01);
        std::copy(&buf[0], &buf[0] + sizeof(int), std::back_inserter(addr));
        return;
    }
    else if (inet_pton(AF_INET6, address.c_str(), buf))
    {   
        addr.push_back(0x04);
        std::copy(&buf[0], &buf[0] + sizeof(struct in6_addr), std::back_inserter(addr)); 
        return;
    }

    if (address.size() > 255)
        address.resize(255);

    addr.push_back(0x03);
    addr.push_back(address.size());
    std::copy(address.begin(), address.end(), std::back_inserter(addr));
}

AddrInfo getaddrinfo(const std::string &addr, const unsigned short int port, const int ai_family, const int socktype, 
                     const int flags, const int protocol)
{
    struct addrinfo hints;
    struct addrinfo *result = nullptr, *rp = nullptr;
    AddrInfo addrs;
    std::stringstream port_str;
    port_str << port;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = ai_family; 
    hints.ai_socktype = socktype; 
    hints.ai_flags = flags;         
    hints.ai_protocol = protocol;          
    hints.ai_canonname = nullptr;
    hints.ai_addr = nullptr;
    hints.ai_next = nullptr;

    if (::getaddrinfo(addr.c_str(), port_str.str().c_str(), &hints, &result) != 0)
        return addrs;

    for (rp = result; rp != nullptr; rp = rp->ai_next)
    {
        int sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;
        close(sfd); 

        if (rp->ai_family == AF_INET && rp->ai_addrlen == sizeof(struct sockaddr_in))
        {
            auto addrv4 = (struct sockaddr_in *)rp->ai_addr;
            addrs.ai_addr_str.resize(INET_ADDRSTRLEN, 0);
            if (!inet_ntop(rp->ai_family, &addrv4->sin_addr, &addrs.ai_addr_str[0], INET_ADDRSTRLEN))
                continue;

            addrs.ai_port = ntohs(addrv4->sin_port);
            break;
        }
        else if (rp->ai_family == AF_INET6 && rp->ai_addrlen == sizeof(struct sockaddr_in6))
        {
            auto addrv6 = (struct sockaddr_in6 *)rp->ai_addr;
            addrs.ai_addr_str.resize(INET6_ADDRSTRLEN, 0);
            if (!inet_ntop(rp->ai_family, &addrv6->sin6_addr, &addrs.ai_addr_str[0], INET6_ADDRSTRLEN))
                continue;
            
            addrs.ai_port = ntohs(addrv6->sin6_port);
            break;
        }
        else if (rp->ai_family == AF_UNIX)
        {
            auto addr_un = (struct sockaddr_un *)rp->ai_addr;
            std::copy(addr_un->sun_path, addr_un->sun_path + sizeof(addr_un->sun_path), std::back_inserter(addrs.ai_addr_str));                  
            addrs.ai_port = 0;
            break;
        }                  
    }

    if (!rp)
    {
        freeaddrinfo(result);
        return addrs;
    }

    addrs.ai_family = rp->ai_family; 
    addrs.ai_socktype = rp->ai_socktype; 
    addrs.ai_protocol = rp->ai_protocol; 
    addrs.ai_addrlen = rp->ai_addrlen;

    auto it = std::find(addrs.ai_addr_str.begin(), addrs.ai_addr_str.end(), 0);
    addrs.ai_addr_str.resize(std::distance(addrs.ai_addr_str.begin(), it));  
    char *addr_ptr = (char *)rp->ai_addr;
    std::copy(addr_ptr, addr_ptr + addrs.ai_addrlen, std::back_inserter(addrs.ai_addr));
    
    freeaddrinfo(result);
    return addrs;
}

uint128& uint128::operator <<=(const size_t pos)
{
    size_t i = 0;
    while (i < pos)
    {
        unsigned long long mask = 1;
        mask <<= 63;
        bool low_bit = _low & mask;
        _high <<= 1;
        _low <<= 1;

        _high |= low_bit;
        i++;
    }

    return *this;
}

uint128 uint128::operator <<(const size_t pos)
{
    size_t i = 0;
    uint128 temp(*this);
    while (i < pos)
    {
        unsigned long long mask = 1;
        mask <<= 63;
        bool low_bit = _low & mask;
        temp._high <<= 1;
        temp._low <<= 1;

        temp._high |= low_bit;
        i++;
    }

    return temp;
}

uint128& uint128::operator >>=(const size_t pos)
{
    size_t i = 0;
    while (i < pos)
    {
        unsigned long long mask = 1;
        unsigned long long high_bit = _high & mask;
        high_bit <<= 63;
        _high >>= 1;
        _low >>= 1;

        _low |= high_bit; 
        i++;
    }

    return *this;
}

uint128 uint128::operator >>(const size_t pos)
{
    size_t i = 0;
    uint128 temp(*this);
    while (i < pos)
    {
        unsigned long long mask = 1;
        unsigned long long high_bit = _high & mask;
        high_bit <<= 63;
        temp._high >>= 1;
        temp._low >>= 1;

        temp._low |= high_bit; 
        i++;
    }

    return temp;
}


bool AddrInfo::operator ==(const AddrInfo &addr) const 
{ 
    auto vec_equal = [] (const std::vector<char> &vecl, const std::vector<char> &vecr)
                    {
                        for (size_t i = 0; i < vecl.size(); i++)
                        {
                            if (vecl[i] != vecr[i])
                                return false;
                        }
                        return true;
                    };

    return ai_family == addr.ai_family && ai_socktype == addr.ai_socktype && ai_protocol == addr.ai_protocol
           && ai_addrlen == addr.ai_addrlen && vec_equal(ai_addr, addr.ai_addr);
}

IPNetwork::IPNetwork(const std::string &addrs)
{
    auto vector_addrs = split(addrs, ",");
    for (auto &addr : vector_addrs)
        add_network(addr);        
}

void IPNetwork::add_network(const std::string &addr)
{
    el::Logger* log = el::Loggers::getLogger("default");
    if (addr.empty())
        return;

    auto block = split(addr, "/");
    int addr_family = is_ip_str(block[0]);
    int addr_len = addr_family == AF_INET ? 32 : addr_family == AF_INET6 ? 128 : 0;
    
    uint128 ip;
    if (addr_family == AF_INET)
    {
        struct in_addr address;
        inet_pton(AF_INET, block[0].c_str(), &address);
        ip._low = ntohl(address.s_addr);
    }
    else if (addr_family == AF_INET6)
    {
        struct in6_addr address;
        inet_pton(AF_INET6, block[0].c_str(), &address);
        ip._high = ntohll(copy_array_to_value<unsigned long long>(address.s6_addr, 0));
        ip._low = ntohll(copy_array_to_value<unsigned long long>(address.s6_addr, 8));
    }
    else
        throw ExceptionInfo("Not a valid CIDR notation: " + addr);

    int prefix_size = 0;
    if (block.size() == 1)
    {
        while ((ip & 1) == 0 && ip != 0)
        {
            ip >>= 1;
            prefix_size += 1;
        }
        log->warn("You did't specify CIDR routing prefix size for %v, implicit treated as %v/%v", addr, addr, addr_len);
    }
    else
    {
        try
        {
            int len = std::stoi(block[1]); //may throw
            if (len <= addr_len)
            {
                prefix_size = addr_len - len;
                ip >>= prefix_size;
            }
            else
                throw ExceptionInfo("Not a valid CIDR notation: " + addr);
        }
        catch (...)
        {
            throw ExceptionInfo("Not a valid CIDR notation: " + addr);
        }
        
    }

    if (addr_family == AF_INET)
        _network_list_v4.push_back(std::make_pair(ip._low, prefix_size));
    else
        _network_list_v6.push_back(std::make_pair(ip, prefix_size));
}

bool IPNetwork::exist(const std::string &addr) const
{
    int addr_family = is_ip_str(addr);

    if (addr_family == AF_INET)
    {
        struct in_addr address;
        inet_pton(AF_INET, addr.c_str(), &address);
        unsigned int ip = ntohl(address.s_addr);  
        return std::any_of(_network_list_v4.begin(), _network_list_v4.end(), 
                          [&](const std::pair<unsigned int, int> &n_ps) { return n_ps.first == (ip >> (size_t)n_ps.second); });
    }

    else if (addr_family == AF_INET6)
    {
        struct in6_addr address;
        inet_pton(AF_INET6, addr.c_str(), &address);
        unsigned long long high = ntohll(copy_array_to_value<unsigned long long>(address.s6_addr, 0));
        unsigned long long low = ntohll(copy_array_to_value<unsigned long long>(address.s6_addr, 8));
        uint128 ip(high, low);
        return std::any_of(_network_list_v6.begin(), _network_list_v6.end(), 
                          [&](const std::pair<uint128, int> &n_ps) { return n_ps.first == (ip >> (size_t)n_ps.second); });
    }

    else
        return false;
}

ExceptionBase::ExceptionBase(const std::string &msg, bool trace_back) throw() :_msg(msg),  _trace_back(trace_back)
{   
    if (trace_back)
        _stack_trace_size = backtrace(_stack_trace, _max_stack_trace_size);
}

const std::string ExceptionBase::get_what_string() const
{
    std::stringstream sstr("");
  
    sstr << get_class_name();
    if (!_msg.empty())
    {
        sstr << ":" << _msg;
    }
    
    if (_trace_back)
    {   
        sstr << "\nstack trace:\n";
        sstr << get_stack_trace();
    }
    return sstr.str();
}

const std::string ExceptionBase::get_stack_trace() const
{
    if (_stack_trace_size == 0)
        return "<No stack trace>\n";
    
    char** strings = backtrace_symbols(_stack_trace, 10);
    if (strings == NULL) // Since this is for debug only thus non-critical, don't throw an exception.
        return "<Unknown error: backtrace_symbols returned NULL>\n";

    std::string result;
    for (size_t i = 0; i < _stack_trace_size; i++)
    {
        std::string mangled_name = strings[i];
        std::string::size_type begin = mangled_name.find('(');
        std::string::size_type end = mangled_name.find('+', begin);
        if (begin == std::string::npos || end == std::string::npos)
        {
            result += mangled_name;
            result += '\n';
            continue;
        }
        ++begin;
        int status;
        char* s = abi::__cxa_demangle(mangled_name.substr(begin, end - begin).c_str(), NULL, 0, &status);
        
        if (status != 0)
        {
            result += mangled_name;
            result += '\n';
            continue;
        }
        std::string demangled_name(s);
        free(s);
        // Ignore ExceptionBase::Init so the top frame is the
        // user's frame where this exception is thrown.
        //
        // Can't just ignore frame#0 because the compiler might
        // inline ExceptionBase::Init.
        result += mangled_name.substr(0, begin);
        result += demangled_name;
        result += mangled_name.substr(end);
        result += '\n';
    }
    free(strings);
    return result;
}
