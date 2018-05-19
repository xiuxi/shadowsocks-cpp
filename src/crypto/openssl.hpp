#ifndef OPENSSL_HPP
#define OPENSSL_HPP

#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "cryptor.hpp"
#include "aead.hpp"


class OpenSSLCryptoBase
{
public:
    OpenSSLCryptoBase() = default;
    OpenSSLCryptoBase(const std::string &cipher_name);
    OpenSSLCryptoBase(const OpenSSLCryptoBase &base) = delete;
    OpenSSLCryptoBase& operator =(const OpenSSLCryptoBase &base) = delete;
    virtual ~OpenSSLCryptoBase() { _destroy(); };
         
protected:
    EVP_CIPHER_CTX *_ctx = nullptr;
    const EVP_CIPHER *_cipher = nullptr;

    void update(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
    void _destroy();
};


class OpenSSLStreamCrypto : public CryptorBase, OpenSSLCryptoBase
{
public:
    OpenSSLStreamCrypto() = default;
    OpenSSLStreamCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv, 
                        const int op);

    OpenSSLStreamCrypto(const OpenSSLStreamCrypto &crypto) = delete;
    OpenSSLStreamCrypto& operator =(const OpenSSLStreamCrypto &crypto) = delete;                 

    void encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        update(in, in_len, out);
    }

    void decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        update(in, in_len, out);
    }
    
    void encrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        update(in, in_len, out);
    }
    void decrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        update(in, in_len, out);
    }

    ~OpenSSLStreamCrypto() = default;  
};

class OpenSSLAeadCrypto : public CryptorBase, OpenSSLCryptoBase, AeadCryptoBase
{
public:
    OpenSSLAeadCrypto() = default;
    OpenSSLAeadCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv, const int op);
    ~OpenSSLAeadCrypto() = default;

    OpenSSLAeadCrypto(const OpenSSLAeadCrypto &crypto) = delete;
    OpenSSLAeadCrypto& operator =(const OpenSSLAeadCrypto &crypto) = delete;

    void encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_base_encrypt(in, in_len, out);  
    }

    void decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_base_decrypt(in, in_len, out); 
    }

    void encrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_encrypt(in, in_len, out);
    }   

    void decrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_decrypt(in, in_len, out);
    }

private:
    void cipher_ctx_init();
    void set_tag(const unsigned char *tag);
    void get_tag(std::vector<unsigned char> &tag_buf);
    void cipher_final(std::vector<unsigned char> &out);
    void aead_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override;
    void aead_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override;               
}; 


#endif