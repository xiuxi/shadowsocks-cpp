#include <set>
#include <map>
#include <unordered_map>
#include <utility>        
#include <algorithm>
#include<iterator> 
#include <sstream>

#include <openssl/md5.h>
#include <openssl/rand.h>

#include "easylogging++.hpp"

#include "cryptor.hpp"
#include "common.hpp"
#include "aead.hpp"
#include "openssl.hpp"
#include "sodium.hpp"


static const std::map<MethodLibs, std::set<InfoMethod>> SUPPORTED_METHOD =
{
    //openssl 
    {
        MethodLibs::OPENSSL, 
        {
            InfoMethod("aes-128-cfb", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("aes-192-cfb", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("aes-256-cfb", MethodLibs::OPENSSL, 32, 16),
            
            InfoMethod("aes-128-ofb", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("aes-192-ofb", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("aes-256-ofb", MethodLibs::OPENSSL, 32, 16),
            
            InfoMethod("aes-128-ctr", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("aes-192-ctr", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("aes-256-ctr", MethodLibs::OPENSSL, 32, 16),
            
            InfoMethod("aes-128-cfb8", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("aes-192-cfb8", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("aes-256-cfb8", MethodLibs::OPENSSL, 32, 16),
            
            InfoMethod("aes-128-cfb1", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("aes-192-cfb1", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("aes-256-cfb1", MethodLibs::OPENSSL, 32, 16),            
            
            InfoMethod("camellia-128-cfb", MethodLibs::OPENSSL, 16, 16),
            InfoMethod("camellia-192-cfb", MethodLibs::OPENSSL, 24, 16),
            InfoMethod("camellia-256-cfb", MethodLibs::OPENSSL, 32, 16),
            
            InfoMethod("bf-cfb", MethodLibs::OPENSSL, 16, 8),
            InfoMethod("cast5-cfb", MethodLibs::OPENSSL, 16, 8),
            InfoMethod("des-cfb", MethodLibs::OPENSSL, 8, 8),
            InfoMethod("idea-cfb", MethodLibs::OPENSSL, 16, 8),
            InfoMethod("rc2-cfb", MethodLibs::OPENSSL, 16, 8),
            InfoMethod("rc4", MethodLibs::OPENSSL, 16, 0),
            InfoMethod("seed-cfb", MethodLibs::OPENSSL, 16, 16)
        }
    },
    
    //openssl aead
    {
        MethodLibs::OPENSSL_AEAD,//AEAD: iv_len = salt_len = key_len
        {
            InfoMethod("aes-128-gcm", MethodLibs::OPENSSL_AEAD, 16, 16),
            InfoMethod("aes-192-gcm", MethodLibs::OPENSSL_AEAD, 24, 24),
            InfoMethod("aes-256-gcm", MethodLibs::OPENSSL_AEAD, 32, 32),
            
            InfoMethod("aes-128-ocb", MethodLibs::OPENSSL_AEAD, 16, 16),
            InfoMethod("aes-192-ocb", MethodLibs::OPENSSL_AEAD, 24, 24),
            InfoMethod("aes-256-ocb", MethodLibs::OPENSSL_AEAD, 32, 32)
        }
    },
    
    //libsodium
    {
        MethodLibs::SODIUM, 
        {
            InfoMethod("salsa20", MethodLibs::SODIUM, 32, 8),
            InfoMethod("chacha20", MethodLibs::SODIUM, 32, 8),
            InfoMethod("xchacha20", MethodLibs::SODIUM, 32, 24),
            InfoMethod("chacha20-ietf", MethodLibs::SODIUM, 32, 12)
        }
    },
    
    //libsodium aead
    {
        MethodLibs::SODIUM_AEAD,  //AEAD: iv_len = salt_len = key_len
        {
            InfoMethod("chacha20-poly1305", MethodLibs::SODIUM_AEAD, 32, 32),
            InfoMethod("chacha20-ietf-poly1305", MethodLibs::SODIUM_AEAD, 32, 32),
            InfoMethod("xchacha20-ietf-poly1305", MethodLibs::SODIUM_AEAD, 32, 32),
            InfoMethod("sodium:aes-256-gcm", MethodLibs::SODIUM_AEAD, 32, 32)
        }
    }
};

static std::unordered_map<std::string, std::vector<unsigned char>> cached_keys;

const InfoMethod get_method(const std::string &method)
{
    MethodLibs method_lib = MethodLibs::NONE;
    std::set<InfoMethod>::iterator it_info_method;
    for (auto it = SUPPORTED_METHOD.begin(); it != SUPPORTED_METHOD.end(); ++it)
    {
        it_info_method = it->second.find(InfoMethod(method));
        if (it_info_method != it->second.end())
        {
           method_lib = it->first;
           break;
        }
    }

    if (method_lib == MethodLibs::NONE)
    {
        throw ExceptionInfo("method " + method + " not supported");
    }
    
    return *it_info_method;
}

static const std::vector<unsigned char>& bytes_to_key(const std::string &password, const size_t key_len, const size_t iv_len)
{   
    std::stringstream cached_key_str;
    cached_key_str << password << key_len << iv_len;
    std::string key_str = cached_key_str.str();
    auto it = cached_keys.find(key_str);
    if (it != cached_keys.end())
        return it->second;
      
    std::vector<unsigned char> key;
    int count = 0;
 
    while (key.size() < key_len)
    {
        std::vector<unsigned char> data;
        static std::vector<unsigned char> out(MD5_DIGEST_LENGTH);        
 
        if (count++)
            data = out; 
        
        std::copy(password.begin(), password.end(), std::back_inserter(data));    
        if (!MD5(&data[0], data.size(), &out[0]))
        {
            throw OpensslError("MD5 error: " + get_opensll_error_str());
        }  
        std::copy(out.cbegin(), out.cend(), std::back_inserter(key));
    }
    
    key.resize(key_len);
    cached_keys[key_str] = key;
    return cached_keys[key_str];
}

static void gen_key_iv_m(const std::string &password, const std::string &method, KEY_IV_M &key_iv_m)
{
    auto m = get_method(method);

    if (m._key_len > 0)
        std::get<0>(key_iv_m) = bytes_to_key(password, m._key_len, m._iv_len);
    else
        std::get<0>(key_iv_m) = std::vector<unsigned char>(password.begin(), password.end());
    
    std::get<1>(key_iv_m).resize(m._iv_len);
    if (RAND_bytes(&std::get<1>(key_iv_m)[0], m._iv_len) <= 0)
    {
        throw OpensslError("RAND_bytes error: " + get_opensll_error_str());
    }

    std::get<2>(key_iv_m) = m;
}

static std::shared_ptr<CryptorBase> get_cipher(std::vector<unsigned char> &key, std::vector<unsigned char> &iv, const InfoMethod &method, const int op)
{
    std::shared_ptr<CryptorBase> cipher;
    
    switch(method._method_lib)
    {
        case MethodLibs::OPENSSL:
            cipher = std::make_shared<OpenSSLStreamCrypto>(method._method, key, iv, op);
            break;
            
        case MethodLibs::OPENSSL_AEAD:
            cipher = std::make_shared<OpenSSLAeadCrypto>(method._method, key, iv, op);
            break;
            
        case MethodLibs::SODIUM:
            cipher = std::make_shared<SodiumStreamCrypto>(method._method, key, iv, op);
            break;
            
        case MethodLibs::SODIUM_AEAD:
            cipher = std::make_shared<SodiumAeadCrypto>(method._method, key, iv, op);
            break;
            
        default:
            break;
    }
    
    if (!cipher)
        throw ExceptionInfo("can not get new cipher");
    
    return cipher;
}

Cryptor::Cryptor(const std::string &password, const std::string &method)
{
    KEY_IV_M key_iv_m;
    gen_key_iv_m(password, method, key_iv_m);
    _method = std::get<2>(key_iv_m);
    
    if (_method._key_len > 0)
    {
        _key = std::get<0>(key_iv_m);
    }
    else
    {
        std::copy(password.begin(), password.end(), std::back_inserter(_key));
        std::get<1>(key_iv_m).clear();
    }
    
    _cipher_iv = std::get<1>(key_iv_m);
    
    _cipher = get_cipher(_key, _cipher_iv, _method, CIPHER_ENC_ENCRYPTION);  
}

void Cryptor::encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    if (in_len == 0)
    {
        out.clear();
        return;
    }
    
    if (_iv_sent)
        _cipher->encrypt(in, in_len, out);
    else
    {
        _iv_sent = true;
        out = _cipher_iv;
        _cipher->encrypt(in, in_len, out);
    }
}

void Cryptor::decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    if (in_len == 0)
    {
        out.clear();
        return;
    }
    
    size_t data_len = in_len;
    if (!_decipher)
    {  
        std::copy(in, in + _method._iv_len, std::back_inserter(_decipher_iv));
        _decipher = get_cipher(_key, _decipher_iv, _method, CIPHER_ENC_DECRYPTION);
        
        data_len -= _method._iv_len;            
        if (!data_len)
        {
            out.clear();
            return;
        }
        in += _method._iv_len;   
    }
    _decipher->decrypt(in, data_len, out);
}

void try_cipher(const std::string &key, const std::string &method)
{
    Cryptor test_cryptor(key, method);
}


void decrypt_all(const std::string &password, const std::string &method, const unsigned char *data, const size_t data_len, 
                 std::vector<unsigned char> &out, std::vector<unsigned char> &key, std::vector<unsigned char> &iv)
{
    KEY_IV_M key_iv_m;
    gen_key_iv_m(password, method, key_iv_m);

    InfoMethod &m = std::get<2>(key_iv_m);
    key = std::get<0>(key_iv_m);
    std::copy(data, data + m._iv_len, std::back_inserter(iv));
    
    auto cipher = get_cipher(key, iv, m, CIPHER_ENC_DECRYPTION);
    cipher->decrypt_once(data + m._iv_len, data_len - m._iv_len, out);
    
}

void decrypt_all(const std::string &password, const std::string &method, const std::vector<unsigned char> &data, std::vector<unsigned char> &out,
                 std::vector<unsigned char> &key, std::vector<unsigned char> &iv)
{
    decrypt_all(password, method, &data[0], data.size(), out, key, iv);
}


void encrypt_all(const std::string &password, const std::string &method, const unsigned char *data, const size_t data_len,
                 std::vector<unsigned char> &out)
{
    KEY_IV_M key_iv_m;
    gen_key_iv_m(password, method, key_iv_m);
    std::vector<unsigned char> &key = std::get<0>(key_iv_m);
    std::vector<unsigned char> &iv = std::get<1>(key_iv_m);
    InfoMethod  &m = std::get<2>(key_iv_m);

    out = iv;
    auto cipher = get_cipher(key, iv, m, CIPHER_ENC_ENCRYPTION);
    cipher->encrypt_once(data, data_len, out);
}

void encrypt_all(const std::string &password, const std::string &method, const std::vector<unsigned char> &data, std::vector<unsigned char> &out)
{
    encrypt_all(password, method, &data[0], data.size(), out);
}
