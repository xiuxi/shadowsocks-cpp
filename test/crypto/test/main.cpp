#include <time.h>
#include <stdio.h>
#include <assert.h>

#include <iostream>
#include <string>
#include <vector>
#include <exception>
#include <random>
#include <chrono>
#include <functional>

#include "easylogging++.hpp"
#include "common.hpp"
#include "cryptor.hpp"
#include "aead.hpp"
#include "openssl.hpp"
#include "sodium.hpp"

INITIALIZE_EASYLOGGINGPP

using namespace std;
using namespace std::chrono;
using namespace std::placeholders;

static vector<unsigned char> uchar_random(size_t size)
{
    static default_random_engine e(time(nullptr));
	static uniform_int_distribution<unsigned char> u;
    
	vector<unsigned char> ret;
	for (size_t i = 0; i < size; i++)
		ret.push_back(u(e));
    
	return ret;
}

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

static void run_cipher(function<void(const unsigned char *, const size_t, vector<unsigned char> &)> cipher, 
                       function<void(const unsigned char *, const size_t, vector<unsigned char> &)> decipher)
{ 
    int block_size = 16384;
    int rounds = 1*1024;
    vector<unsigned char> random_plain_text = uchar_random(block_size * rounds); 
    vector<vector<unsigned char>> cipher_results;
    vector<unsigned char> plain_text_results;
    
    size_t pos = 0;
    size_t size = random_plain_text.size();
    default_random_engine e(time(nullptr));
	uniform_int_distribution<int> u(100, 32768);
    
    high_resolution_clock::time_point start = high_resolution_clock::now();
    while (pos < size)
    {
        int len = u(e);
        if (pos + len > size)
            len = size - pos;
 
        vector<unsigned char> out;
        cipher(&random_plain_text[pos], len, out);
        cipher_results.push_back(out);
        pos += len;
    }

    for (auto &c : cipher_results)
    {
        vector<unsigned char> out;
        decipher(&c[0], c.size(), out);
        copy(out.begin(), out.end(), back_inserter(plain_text_results));
    }
    high_resolution_clock::time_point end = high_resolution_clock::now();
    duration<double> time_span = duration_cast<duration<double>>(end - start);
    printf("speed: %f kb/s\n", (double)(block_size * rounds) / time_span.count() / 1024);
    assert(equal_vector(random_plain_text, plain_text_results));
}


static void run_openssl_stream_method(const std::string &method)
{    
    cout << "test start, run stream method: " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(16, 'i');
    OpenSSLStreamCrypto cipher(method, key, iv, 1);
    OpenSSLStreamCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&OpenSSLStreamCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&OpenSSLStreamCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_openssl_aead_method(const std::string &method)
{
    cout << "test start, run aead method: [payload][tag] " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(32, 'i');
    OpenSSLAeadCrypto cipher(method, key, iv, 1);
    OpenSSLAeadCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&OpenSSLAeadCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&OpenSSLAeadCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_openssl_aead_method_chunk(const std::string &method)
{
    cout << "test start, run aead method: chunk([size][tag][payload][tag] " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(32, 'i');
    OpenSSLAeadCrypto cipher(method, key, iv, 1);
    OpenSSLAeadCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&OpenSSLAeadCrypto::encrypt, &cipher, _1, _2, _3), 
               bind(&OpenSSLAeadCrypto::decrypt, &decipher, _1, _2, _3));
}

static void run_sodium_salsa20_chacha20(const std::string &method)
{
    cout << "test start, run stream method: " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(8, 'i');
    SodiumStreamCrypto cipher(method, key, iv, 1);
    SodiumStreamCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&SodiumStreamCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&SodiumStreamCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_sodium_xchacha20()
{
    cout << "test start, run stream method: xchacha20"<< " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(24, 'i');
    SodiumStreamCrypto cipher("xchacha20", key, iv, 1);
    SodiumStreamCrypto decipher("xchacha20", key, iv, 0);

    run_cipher(bind(&SodiumStreamCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&SodiumStreamCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_sodium_chacha20_ietf()
{
    cout << "test start, run stream method: chacha20-ietf" << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(24, 'i');
    SodiumStreamCrypto cipher("chacha20-ietf", key, iv, 1);
    SodiumStreamCrypto decipher("chacha20-ietf", key, iv, 0);

    run_cipher(bind(&SodiumStreamCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&SodiumStreamCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_sodium_aead_method(const std::string &method)
{
    cout << "test start, run aead method: [payload][tag] " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(32, 'i');
    SodiumAeadCrypto cipher(method, key, iv, 1);
    SodiumAeadCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&SodiumAeadCrypto::encrypt_once, &cipher, _1, _2, _3), 
               bind(&SodiumAeadCrypto::decrypt_once, &decipher, _1, _2, _3));
}

static void run_sodium_aead_method_chunk(const std::string &method)
{
    cout << "test start, run aead method: chunk([size][tag][payload][tag] " << method << " " << 32 << "\n";
    vector<unsigned char> key(32, 'k');
    vector<unsigned char> iv(32, 'i');
    SodiumAeadCrypto cipher(method, key, iv, 1);
    SodiumAeadCrypto decipher(method, key, iv, 0);

    run_cipher(bind(&SodiumAeadCrypto::encrypt, &cipher, _1, _2, _3), 
               bind(&SodiumAeadCrypto::decrypt, &decipher, _1, _2, _3));
}

static void run_cryptor(Cryptor &cipher, Cryptor &decipher)
{
    int block_size = 16384;
    int rounds = 1*1024;
    vector<unsigned char> random_plain_text = uchar_random(block_size * rounds); 
    vector<vector<unsigned char>> cipher_results;
    vector<unsigned char> plain_text_results;
    
    size_t pos = 0;
    size_t size = random_plain_text.size();
    default_random_engine e(time(nullptr));
	uniform_int_distribution<int> u(100, 32768);
    
    high_resolution_clock::time_point start = high_resolution_clock::now();
    while (pos < size)
    {
        int len = u(e);
        if (pos + len > size)
            len = size - pos;
 
        vector<unsigned char> out;
        cipher.encrypt(&random_plain_text[pos], len, out);
        cipher_results.push_back(out);
        pos += len;
    }

    for (auto &c : cipher_results)
    {
        vector<unsigned char> out;
        decipher.decrypt(c, out);
        copy(out.begin(), out.end(), back_inserter(plain_text_results));
    }
    high_resolution_clock::time_point end = high_resolution_clock::now();
    duration<double> time_span = duration_cast<duration<double>>(end - start);
    printf("speed: %f kb/s\n", (double)(block_size * rounds) / time_span.count() / 1024);
    assert(equal_vector(random_plain_text, plain_text_results));
}


int main(int argc, char *argv[])
{   
    vector<string> test_cipher = {
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-ofb",
        "aes-192-ofb",
        "aes-256-ofb",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb8",
        "aes-192-cfb8",
        "aes-256-cfb8",
        "aes-128-cfb1",
        "aes-192-cfb1",
        "aes-256-cfb1",
        "camellia-128-cfb",
        "camellia-192-cfb",
        "camellia-256-cfb",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "rc4",
        "seed-cfb",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "aes-128-ocb",
        "aes-192-ocb",
        "aes-256-ocb",
        "salsa20",
        "chacha20",
        "xchacha20",
        "chacha20-ietf",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "sodium:aes-256-gcm"
    };
    
    try
    {
        std::cout << "Encryption method support test start:" << std::endl;
        for (auto &c : test_cipher)
            try_cipher("123456789", c);       
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    
    try
    {
        try_cipher("123456789", "bad method"); 
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    
    std::cout << "Encryption method support test end" << std::endl;
    
    std::cout << "Encryption method speed test start:" << std::endl;   
    try
    {
        for (auto &c : test_cipher)
        {
            Cryptor cipher("key", c);
            Cryptor decipher("key", c);
            cout << c << ": ";
            run_cryptor(cipher, decipher);
        }
        
    }
    
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    std::cout << "Encryption method speed test end" << std::endl;
    
    std::cout << "the original method speed test start:" << std::endl;
    vector<string> openssl_stream_cipher = {
        
        "aes-256-cfb",
        "aes-256-cfb8",
        "aes-256-cfb1",
        "aes-256-ofb",
        "aes-256-ctr",
        "camellia-256-cfb"
    };
    
    for(auto &c : openssl_stream_cipher)
    {
        run_openssl_stream_method(c);
    }
    
    run_openssl_aead_method("aes-256-gcm");
    run_openssl_aead_method("aes-256-ocb");
    run_openssl_aead_method_chunk("aes-256-gcm");
    run_openssl_aead_method_chunk("aes-256-ocb");
    
    run_sodium_salsa20_chacha20("salsa20");
    run_sodium_salsa20_chacha20("chacha20");
    run_sodium_xchacha20();
    run_sodium_chacha20_ietf();
    
    run_sodium_aead_method("chacha20-poly1305");
    run_sodium_aead_method("chacha20-ietf-poly1305");
    run_sodium_aead_method("xchacha20-ietf-poly1305");
    try
    {
        run_sodium_aead_method("sodium:aes-256-gcm");
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
        
    run_sodium_aead_method_chunk("chacha20-poly1305");
    run_sodium_aead_method_chunk("chacha20-ietf-poly1305");
    run_sodium_aead_method_chunk("xchacha20-ietf-poly1305");
    try
    {
        run_sodium_aead_method_chunk("sodium:aes-256-gcm");
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    std::cout << "the original method speed test end" << std::endl;
    return 0; 
}