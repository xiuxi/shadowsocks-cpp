#ifndef SODIUM_HPP
#define SODIUM_HPP

#include <stdint.h>
#include <string>
#include <vector>

#include "cryptor.hpp"
#include "aead.hpp"


class SodiumStreamCrypto : public CryptorBase
{
public:
    SodiumStreamCrypto() = default;
    SodiumStreamCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv, 
                       const int op);
    ~SodiumStreamCrypto() = default;

    SodiumStreamCrypto(const SodiumStreamCrypto &crypto) = delete;
    SodiumStreamCrypto& operator =(const SodiumStreamCrypto &crypto) = delete;

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


private:
    std::vector<unsigned char> _key;
    std::vector<unsigned char> _iv;
    int (*_cipher)(unsigned char *, const unsigned char *, unsigned long long, const unsigned char *, uint64_t, const unsigned char *) = nullptr;
    unsigned long long int _counter = 0; //may overflow

    void update(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
};


class SodiumAeadCrypto :public CryptorBase, AeadCryptoBase
{
public:
    SodiumAeadCrypto() = default;
    SodiumAeadCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv, 
                     const int op);
    ~SodiumAeadCrypto() = default;

    SodiumAeadCrypto(const SodiumAeadCrypto &crypto) = delete;
    SodiumAeadCrypto& operator =(const SodiumAeadCrypto &crypto) = delete;

    void encrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_encrypt(in, in_len, out);
    }

    void decrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_decrypt(in, in_len, out);
    }

    void encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_base_encrypt(in, in_len, out);
    }

    void decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override
    {
        aead_base_decrypt(in, in_len, out);
    }

private:
    int (*_encryptor)(unsigned char *, 
                      unsigned long long *, 
                      const unsigned char *, 
                      unsigned long long, 
                      const unsigned char *, 
                      unsigned long long, 
                      const unsigned char *, 
                      const unsigned char *, 
                      const unsigned char *) = nullptr;
    int (*_decryptor)(unsigned char *,
                      unsigned long long *,
                      unsigned char *,
                      const unsigned char *,
                      unsigned long long,
                      const unsigned char *,
                      unsigned long long,
                      const unsigned char *,
                      const unsigned char *) = nullptr;

    void aead_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override;
    void aead_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) override;
    void cipher_ctx_init();
};

#endif