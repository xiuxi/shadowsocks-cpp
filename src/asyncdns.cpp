#include <arpa/inet.h>

#include <algorithm>
#include <iterator>
#include <tuple>
#include <regex>
#include <fstream>
#include <utility>

#include "easylogging++.hpp"

#include "common.hpp"
#include "asyncdns.hpp"

/*
# rfc1035
# format 
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+

# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# question
# 
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     / variable length 
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     | 16 bites
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    | 16 bites
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

#define QTYPE_ANY  255
#define QTYPE_A  1
#define QTYPE_AAAA  28
#define QTYPE_CNAME  5
#define QTYPE_NS 2
#define QCLASS_IN  1

#define HEADER_SIZE 12
#define QTYPE_SIZE 2
#define QCLASS_SIZE 2
#define QTYPE_QCLASS_SIZE 4

#define HEADER_ID_POS 0
#define HEADER_FLAG_POS 2
#define HEADER_QDCOUNT_POS 4
#define HEADER_ANCOUNT_POS 6
#define HEADER_NSCOUNT_POS 8
#define HEADER_ARCOUNT_POS 10

#define QNAME_POS 12

//"www.google.com" to "3www6google3com\0" 
static bool build_address(const std::string &address, std::vector<unsigned char> &results)
{
    auto addr = strip(address, ".");
    auto labels = split(addr, ".");  
    
    for (auto &label : labels)
    {
        auto len = label.size();
        if ( len > 63)
            return false;

        results.push_back((unsigned char)len);
        std::copy(label.cbegin(), label.cend(), std::back_inserter(results));
    }
    results.push_back(0);
    return true;   
}

//build dns request
static bool build_request(const std::string &address, const int qtype, std::vector<unsigned char> &request)
{
    std::vector<unsigned char> addr;
    if (!build_address(address, addr))
        return false;
    
    request.resize(HEADER_SIZE + addr.size() + QTYPE_QCLASS_SIZE, 0); 
    auto request_id = uint_random(2);

    //dns header
    copy_value_to_vector((unsigned short int)request_id, request, 0); //ID
    copy_value_to_vector(htons(0x0100), request, HEADER_FLAG_POS); //FLAG
    copy_value_to_vector(htons(0x0001), request, HEADER_QDCOUNT_POS); //QDCOUNT

    //question
    std::copy(addr.begin(), addr.end(), request.begin() + QNAME_POS); //QNAME
    copy_value_to_vector(htons(qtype), request, request.size() - QTYPE_QCLASS_SIZE); //QTYPE
    copy_value_to_vector(htons(QCLASS_IN), request, request.size() - QCLASS_SIZE); //QCLASS

    return true;
}


static std::pair<int, std::string> parse_name(const std::vector<unsigned char> &data, const int offset)
{
    int pos = offset;
    std::string labels;
    unsigned char len = data[pos]; //len or pointer
    while (len > 0)
    {
        if ((len & 0xc0) == 0xc0) //pointer
        {
            //pointer   
            unsigned short int pointer = ntohs(copy_vector_to_value<unsigned short int>(data, pos));
            pointer &= 0x3fff; 
            auto ret = parse_name(data, pointer);
            std::copy(ret.second.begin(), ret.second.end(), std::back_inserter(labels));
            pos += 2;
            //pointer is the end

            return std::make_pair(pos - offset, labels);
        }
        else //len + name
        {	
            std::copy(data.cbegin() + pos + 1, data.cbegin() + pos + 1 + len, std::back_inserter(labels));
            labels.push_back('.');
            pos += len + 1; 
        }
        len = data[pos];
    }
    
    labels.pop_back(); //remove the last value '.'
    return std::make_pair(pos - offset + 1, labels);
}

static std::string parse_ip(const std::vector<unsigned char> &data,  const int addrtype, const int length, const int offset)
{
    if (addrtype == QTYPE_A)
    {
        struct in_addr addr;
        addr.s_addr = copy_vector_to_value<unsigned int>(data, offset);
        std::string ip_str(INET_ADDRSTRLEN, 0);
        if (!inet_ntop(AF_INET, &addr, &ip_str[0], INET_ADDRSTRLEN))
            ip_str.clear();

        auto it = std::find(ip_str.begin(), ip_str.end(), 0);
        ip_str.resize(std::distance(ip_str.begin(), it));
        return ip_str;
    }
    else if (addrtype == QTYPE_AAAA)
    {
        struct in6_addr addr;
        std::copy(data.begin() + offset, data.begin() + offset + length, addr.s6_addr);
        std::string ip_str(INET6_ADDRSTRLEN, 0);
        if (!inet_ntop(AF_INET, &addr, &ip_str[0], INET6_ADDRSTRLEN))
            ip_str.clear();

        auto it = std::find(ip_str.begin(), ip_str.end(), 0);
        ip_str.resize(std::distance(ip_str.begin(), it));
        
        return ip_str;
    }
    else if (addrtype == QTYPE_CNAME || addrtype == QTYPE_NS)
    {
        return parse_name(data, offset).second;
    }
    else
    {
        return  std::string(data.begin() + offset, data.begin() + offset + length);
    }
}

/*
# rfc1035
# record
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

using record_info = std::tuple<std::string, std::string, unsigned short int, unsigned short int, unsigned int>;

static void parse_record(const std::vector<unsigned char> &data, const int offset, std::pair<int, record_info> &ret, bool question = false)
{
    auto length_name = parse_name(data, offset);
    if (!question)
    {
        std::get<0>(ret.second) = length_name.second;
        std::get<2>(ret.second) = ntohs(copy_vector_to_value<unsigned short int>(data, offset + length_name.first)); //TYPE
        std::get<3>(ret.second) = ntohs(copy_vector_to_value<unsigned short int>(data, offset + length_name.first + 2));//CLASS
        //std::get<4>(ret.second) = ntohs(copy_vector_to_value<unsigned int>(data, offset + length_name.first + 4)); //TTL, for now no need
        auto record_rdlength = ntohs(copy_vector_to_value<unsigned short int>(data, offset + length_name.first + 8)); //RDLENGTH       
        std::get<1>(ret.second) = parse_ip(data, std::get<2>(ret.second), record_rdlength, offset + length_name.first + 10);//RDATA
        ret.first = length_name.first + 10 + record_rdlength;       
    }
    else //question
    {
        ret.first = length_name.first + 4;
        std::get<0>(ret.second) = length_name.second;
        std::get<1>(ret.second) = "";
        std::get<2>(ret.second) = ntohs(copy_vector_to_value<unsigned short int>(data, offset + length_name.first)); //TYPE
        std::get<3>(ret.second) = ntohs(copy_vector_to_value<unsigned short int>(data, offset + length_name.first + 2)); //CLASS
        //std::get<4>(ret.second) = 0; //TTL, for now no need
    }
}

static std::vector<unsigned short int> dns_parse_header(const std::vector<unsigned char> &header)
{
    std::vector<unsigned short int> res;
    if (header.size() >= HEADER_SIZE)
    { 
        res.push_back(ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_ID_POS))); //id 0
        auto res_flag = ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_FLAG_POS)); 
        res.push_back(res_flag & 0x8000); //qr 1
        res.push_back(res_flag & 0x0200); //tc 2
        res.push_back(res_flag & 0x0080); //ra 3
        res.push_back(res_flag & 0x000f); //rcode 4
        res.push_back(ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_QDCOUNT_POS))); // QDCOUNT 5
        res.push_back(ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_ANCOUNT_POS))); // ANCOUNT 6
        res.push_back(ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_NSCOUNT_POS))); // NSCOUNT 7
        res.push_back(ntohs(copy_vector_to_value<unsigned short int>(header, HEADER_ARCOUNT_POS))); // ARCOUNT 8     
    }

    return res;
}

struct DNSResponse
{
    std::string hostname;
    std::vector<std::tuple<std::string, unsigned short int, unsigned short int>> questions; //each: (addr, type, class)
    std::vector<std::tuple<std::string, unsigned short int, unsigned short int>> answers; //each: (ip, type, class)
    explicit operator bool () { return !hostname.empty();}
};

static DNSResponse parse_response(const std::vector<unsigned char> &data)
{
    DNSResponse response;
    if (data.size() >= HEADER_SIZE)
    {
        auto header = dns_parse_header(data);
        if (header.empty())
            return response;

        std::pair<int, record_info> ret;
        int offset = 12;
        
        for (unsigned short int i = 0; i < header[5]; i++)// QDCOUNT 5
        {
            parse_record(data, offset, ret, true);
            offset += ret.first;
            if (i == 0)
                response.hostname = std::get<0>(ret.second);
            
            response.questions.push_back(std::make_tuple(std::get<1>(ret.second), std::get<2>(ret.second), std::get<3>(ret.second)));
        }
        
        for (unsigned short int i = 0; i < header[6]; i++)// ANCOUNT 6
        {
            parse_record(data, offset, ret);
            offset += ret.first;
            response.answers.push_back(std::make_tuple(std::get<1>(ret.second), std::get<2>(ret.second), std::get<3>(ret.second)));
        }  
         /* for now no need to handle
        for (unsigned short int i = 0; i < header[7]; i++)// NSCOUNT 7
        {
            parse_record(data, offset, ret);
            offset += ret.first;
        }
        
        for (unsigned short int i = 0; i < header[8]; i++)// ARCOUNT 8 
        {
            parse_record(data, offset, ret);
            offset += ret.first;
        }
        */
    }
    else
        LOG(DEBUG) << "data too short";
 
    return response;
}

static bool is_valid_hostname(const std::string &hostname)
{
    static std::regex reg("(?!-)[[:alnum:]\\-_]{1,63}$");
    
    if (hostname.size() > 255)
        return false;

    auto names = split(hostname, ".");
    for (auto &name : names)
    {
        if (name[name.size() - 1] == '-')
            return false;
        if (!std::regex_match(name, reg))
            return false;
    }

    return true;
}

#define STATUS_FIRST  0
#define STATUS_SECOND  1

DNSResolver::DNSResolver(const std::vector<std::string> &server_list, bool prefer_ipv6) : _cache(300)
{
    if (server_list.empty())
       _parse_resolv();
    else
        _servers = server_list;

    if (prefer_ipv6)
        _QTYPES = {QTYPE_AAAA, QTYPE_A}; 
    else
        _QTYPES = {QTYPE_A, QTYPE_AAAA};

    _parse_hosts();
    // TODO monitor hosts change and reload hosts
    // TODO parse /etc/gai.conf and follow its rules
}

void DNSResolver::_parse_resolv()
{    
    try
    {   
        std::ifstream fs("/etc/resolv.conf", std::fstream::in);
        std::string line;
        while (getline(fs, line))
        {
            line = strip(line, " "); 
            if (line.empty() || !start_with(line, "nameserver"))
                continue;

            auto parts = split(line, " ");
            if (parts.size() < 2)
                continue;

            auto server = parts[1];
            if (is_ip_str(server) == AF_INET)
                _servers.push_back(server);
        }
    }
    catch(std::exception &e)
    {
        _servers.clear();
    }
    if (_servers.empty())
        _servers = {"1.1.1.1", "1.0.0.1"}; 
}

void DNSResolver::_parse_hosts()
{
    try
    {
        std::ifstream fs("/etc/hosts", std::fstream::in);
        std::string line;
        while (getline(fs, line))
        {
            line = strip(line, " ");
            auto parts = split(line, " ");
            if (parts.size() < 2)
                continue;

            auto ip = parts[0];
            if (is_ip_str(ip) < 0)
                continue;

            for (size_t i = 1; i < parts.size(); i++)
            {
                auto hostname = parts[i];
                if (!hostname.empty())
                    _hosts[hostname] = ip;
            }
        }
    }
    catch(std::exception &e)
    {
        _hosts.clear();
        _hosts["localhost"] = "127.0.0.1";
    }       
}

void DNSResolver::add_to_loop(std::shared_ptr<EventLoop> &loop)
{
    if (_loop)
        throw ExceptionInfo("already add to loop");

    _loop = loop;
    // TODO when dns server is IPv6

    _sock = Socket(AF_INET, SOCK_DGRAM, 0);
    _sock.set_sock_blocking(false);
    _loop->add(_sock.get_socket(), EPOLLIN, this);
    _loop->add_periodic(this);
}


void DNSResolver::_call_callback(const std::string &hostname, const std::string &ip, const std::string &error)
{
    auto hds_it = _hostname_to_vector_hd.find(hostname); //_hostname_to_vector_hd: {hostname : std::vector<handler>}
    if (hds_it != _hostname_to_vector_hd.end())
    {
        for (auto &hd : hds_it->second)//for each handle
        { 
            auto it = _hd_to_hostname.find(hd); //_hd_to_hostname: {handler : hostname}
            if ( it != _hd_to_hostname.end())  
                _hd_to_hostname.erase(it);

             //call the handle callback function
            if (!ip.empty() || !error.empty())
                hd->handle_dns_resolved(hostname, ip, error);
            else
                hd->handle_dns_resolved(hostname, "", "unknown hostname " + hostname);
        }
        _hostname_to_vector_hd.erase(hds_it); //the hostname have been solved, so erase it
    }

    auto it = _hostname_status.find(hostname);
    if (it != _hostname_status.end())
        _hostname_status.erase(it);
}

void DNSResolver::_handle_data(const std::vector<unsigned char> &data)
{
    auto response = parse_response(data);
    if (response)
    {
        auto &hostname = response.hostname;
        std::string ip;
        
        for (auto &answer : response.answers)
        {
            auto &type = std::get<1>(answer);
            auto &class_in = std::get<2>(answer);
            
            if ((type == QTYPE_A || type == QTYPE_AAAA) && class_in == QCLASS_IN)
            {
                ip = std::get<0>(answer);
                break;
            }
        }
        
        int status = -1;
        auto it = _hostname_status.find(hostname);
        if (it != _hostname_status.end())
             status = it->second;
        
        if  (ip.empty() && status == STATUS_FIRST) //using second type to resolve again 
        {
            _hostname_status[hostname] = STATUS_SECOND;
            _send_req(hostname, _QTYPES[1]);
        }
        else
        {
            if (!ip.empty())
            {
                _cache.set(hostname, ip);
                _call_callback(hostname, ip);
            }
            else if (status == STATUS_SECOND) //has been resolved a second time but ip still null, call the callback function
            {
                for (auto &question : response.questions)
                {
                    if (std::get<1>(question) == _QTYPES[1]) 
                    {
                        _call_callback(hostname);
                        break;
                    }
                }
            }
        }
    }
}

void DNSResolver::handle_event(const int fd, const unsigned int event)
{
    if (fd != _sock.get_socket())
        return;
    
    try
    {
        if (event & EPOLLERR)
        {
            LOG(ERROR) << "dns socket err";
            _loop->remove(fd);
            
            // TODO when dns server is IPv6
            
            //make sure the new dns socket will epoll even though the old socket close error
            Socket new_sock(AF_INET, SOCK_DGRAM, 0);            
            try
            {
                new_sock.set_sock_blocking(false);
                _loop->add(new_sock.get_socket(), EPOLLIN, this);
            }
            catch (SysError &error)
            {
                LOG(ERROR) << error.what();
                exit(1);
            } 
            _sock = new_sock;
        }
        else
        {
            std::vector<unsigned char> data;
            std::pair<std::string, unsigned short int> addr;
            auto ret_size = _sock.recvfrom(data, 1024, addr);
            auto it = std::find(_servers.begin(), _servers.end(), addr.first);
            if (it == _servers.end())
            {
                LOG(WARNING) << "received a packet other than our dns";
                return ;
            }

            data.resize(ret_size);
            _handle_data(data);
        }
    }
    catch (SysError &error) 
    {
        if (errno == EMFILE || errno == ENFILE) //No more file descriptors are available
        {
            LOG(ERROR) << error.what();
            exit(1);
        }
    }
    catch (ExceptionInfo &info)
    {
        LOG(WARNING) << info.what();
    }
}

void DNSResolver::remove_callback(DNSHandle *hd)
{ 
    auto it = _hd_to_hostname.find(hd); 
    if (it != _hd_to_hostname.end())
    {
        auto hostname = it->second;
        _hd_to_hostname.erase(it); //delete from the _hd_to_hostname

        auto it_arr = _hostname_to_vector_hd.find(hostname);
        if (it_arr != _hostname_to_vector_hd.end()) //hostname in the _hostname_to_vector_hd
        {
            auto call_back_it = std::find(it_arr->second.begin(), it_arr->second.end(), hd);
            if (call_back_it != it_arr->second.end())
                it_arr->second.erase(call_back_it);

            if (it_arr->second.empty()) //the hostname don't have any handle
            {
                _hostname_to_vector_hd.erase(it_arr);
                
                if (_hostname_status.find(hostname) != _hostname_status.end())
                    _hostname_status.erase(hostname);
            }
        }
    }
}

void DNSResolver::_send_req(const std::string &hostname, const int qtype)
{
    std::vector<unsigned char> req;
    if (!build_request(hostname, qtype, req))
        return ;
    
    for (auto &server : _servers)
    { 
        LOG(DEBUG) << "resolving " + hostname + " with type " << qtype << " using server " +  server;
        try
        {
            _sock.sendto(req, std::make_pair(server, 53));
        }
        catch(...)
        {
            return;
        }
    }
}

void DNSResolver::resolve(const std::string &hostname, DNSHandle *hd)
{
    auto it_hosts = _hosts.find(hostname); 
    if (hostname.empty())
    {
        hd->handle_dns_resolved("", "", "empty hostname");
    }
    else if (is_ip_str(hostname) != -1)
    {
        hd->handle_dns_resolved(hostname, hostname, "");
    }
    else if (it_hosts != _hosts.end())
    { 
        LOG(DEBUG) << "hit hosts: " + hostname;
        hd->handle_dns_resolved(hostname, it_hosts->second, "");
    }
    else if (_cache.exist(hostname))
    {
        LOG(DEBUG) << "hit cache: " + hostname;
        auto ip = _cache.get(hostname);
        hd->handle_dns_resolved(hostname, ip, "");
    }
    else
    {
        if (!is_valid_hostname(hostname))
        { 
            hd->handle_dns_resolved("", "", "invalid hostname: " + hostname);
            return ;
        }
        auto it_ary = _hostname_to_vector_hd.find(hostname); //_hostname_to_vector_hd {hostname : std::vector<handler>}
        if  (it_ary == _hostname_to_vector_hd.end())
        {
            _hostname_status[hostname] = STATUS_FIRST; 
            _send_req(hostname, _QTYPES[0]);
            _hostname_to_vector_hd[hostname].push_back(hd);           
            _hd_to_hostname[hd] = hostname; //_hd_to_hostname: {handler : hostname}  
        }
        else
        {
            it_ary->second.push_back(hd);
            // TODO send again only if waited too long
            _send_req(hostname, _QTYPES[0]);// 
        }
    }
}

void DNSResolver::_destory()
{ 
    if(_loop)
    {
        _loop->remove_periodic(this);
        _loop->remove(_sock.get_socket());
    } 
}