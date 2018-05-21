#ifndef COMMON_HPP
#define COMMON_HPP

#include <vector>
#include <string>
#include <exception>
#include <tuple>

struct AddrInfo;

void init_easylog();

std::string get_std_error_str();

std::string get_opensll_error_str();

bool start_with(const std::string &str, const std::string &chars);

bool end_with(const std::string &str, const std::string &chars);

unsigned int uint_random(const int size); 

int is_ip_str(const std::string &address);

std::string strip(const std::string &str, const std::string &chars);

std::vector<std::string> split(const std::string &str, const std::string &sep, int max_split = -1);

std::vector<std::string> rsplit(const std::string &str, const std::string &sep, int max_split = -1);
                        
std::tuple<unsigned char, std::string, unsigned short int, unsigned int> parse_header(const std::vector<unsigned char> &data);

void pack_addr(std::string &address, std::vector<unsigned char> &addr);

AddrInfo getaddrinfo(const std::string &addr, const unsigned short int port, const int ai_family, const int socktype, 
                     const int flags, const int protocol);

template<typename type_value, typename type_vector>
void copy_value_to_vector(const type_value &value, std::vector<type_vector> &vec, const size_t pos)
{
    union
    {
        type_value first;
        type_vector second[sizeof(type_value)];
    } type_array;
    
    type_array.first = value;
    std::copy(type_array.second, type_array.second + sizeof(type_value), vec.begin() + pos);
}

template<typename type_value, typename type_vector>
type_value copy_vector_to_value(const std::vector<type_vector> &vec, const size_t pos)
{
    union
    {
        type_value first;
        type_vector second[sizeof(type_value)];
    } type_array;
    
    std::copy(vec.begin() + pos, vec.begin() + pos + sizeof(type_value), type_array.second);
    return type_array.first;   
}


template<typename type_value, typename type_array_point>
type_value copy_array_to_value(const type_array_point *array, const size_t pos)
{
    union
    {
        type_value first;
        type_array_point second[sizeof(type_value)];
    } type_array;
    
    std::copy(array + pos, array + pos + sizeof(type_value), type_array.second);
    return type_array.first;   
}
                 
class uint128
{
public:
    uint128() = default;
    template<typename T> uint128(const T &high, const T &low) : _high(high), _low(low) {}
    template<typename T> uint128(const T &low) : _high(0), _low(low) {}
    uint128(const uint128 &t) : _high(t._high), _low(t._low){}
    uint128& operator=(const uint128 &t) { _high = t._high; _low = t._low; return *this;}
    ~uint128() = default;
    
    uint128& operator <<=(const size_t pos);
    uint128 operator <<(const size_t pos);
    uint128 & operator >>=(const size_t pos);
    uint128 operator >>(const size_t pos);

    template<typename T> 
    uint128 & operator &=(const T &_T)
    {
        uint128 temp(_T);
        _high &= temp._high;
        _low &= temp._low;                

        return *this;
    }

    template<typename T> 
    uint128 operator &(const T &_T) const
    {
        uint128 temp(_T);
        uint128 out;
        out._high = _high & temp._high;
        out._low = _low & temp._low;  

        return out;
    }

    template<typename T>
    bool operator ==(const T &_T) const
    {
    	uint128 temp(_T);
        return _low == temp._low && _high == temp._high;
    }

	template<typename T>
    bool operator !=(const T &_T) const
    {
        return !(*this == _T);
    }
	
	template<typename T>
    bool operator <(const T &_T) const
    {
    	uint128 temp(_T);
        return  (_high < temp._high || _low < temp._low);
    }  

	template<typename T>
    bool operator >(const T &_T) const
    {
    	uint128 temp(_T);
        return _low > temp._low || _high > temp._high;
    }

    unsigned long long _high = 0;
    unsigned long long _low = 0;
};

struct AddrInfo 
{
    AddrInfo() = default;
    ~AddrInfo() = default;  
    int ai_family = 0;
    int ai_socktype = 0;
    int ai_protocol = 0;
    std::string ai_addr_str;
    unsigned short int ai_port;
    size_t ai_addrlen = 0;
    std::vector<char> ai_addr;
    
    bool empty() const { return ai_addr.empty();}
    bool operator ==(const AddrInfo &addr) const; 
    bool operator !=(const AddrInfo &addr) const { return !(*this == addr); }  
};

class IPNetwork
{
public:
    IPNetwork() = default;
    IPNetwork(const std::string &addrs);
    void add_network(const std::string &addr);
    bool exist(const std::string &addr) const;

private:
    std::vector<std::pair<unsigned int, int>> _network_list_v4;
    std::vector<std::pair<uint128, int>> _network_list_v6;
};

class ExceptionBase : public std::exception
{
public:
    ExceptionBase(const std::string &msg, bool trace_back = false) throw();    
    const char* what() const throw() 
    {
        _what = get_what_string();
        return _what.c_str(); 
    }
    virtual ~ExceptionBase() throw(){}

protected:
    virtual const std::string get_class_name() const = 0;

private:
    std::string _msg;
    bool _trace_back;
    mutable std::string _what;
    const static size_t _max_stack_trace_size = 50;
    void* _stack_trace[_max_stack_trace_size];
    size_t _stack_trace_size = 0;
    const std::string get_what_string() const;
    const std::string get_stack_trace() const;
};

class ExceptionInfo : public ExceptionBase
{
public:
    ExceptionInfo(const std::string &msg, bool trace_back = false) throw() : ExceptionBase(msg, trace_back){}    
    ~ExceptionInfo() throw(){}
protected:
    const std::string get_class_name() const override { return "ExceptionInfo"; }
};

class SysError : public ExceptionBase
{
public:
    SysError(const std::string &msg, bool trace_back = false) throw() : ExceptionBase(msg, trace_back){}    
    ~SysError() throw(){}
protected:
    const std::string get_class_name() const override { return "SysError"; }
};

class OpensslError : public ExceptionBase
{
public:
    OpensslError(const std::string &msg, bool trace_back = false) throw() : ExceptionBase(msg, trace_back){}    
    ~OpensslError() throw(){}
protected:
    const std::string get_class_name() const override { return "OpensslError"; }
};

class SodiumError : public ExceptionBase
{
public:
    SodiumError(const std::string &msg, bool trace_back = false) throw() : ExceptionBase(msg, trace_back){}    
    ~SodiumError() throw(){}
protected:
    const std::string get_class_name() const override { return "SodiumError"; }
};

#endif