#include <sodium.h>

#include "easylogging++.hpp"
#include "sodium.hpp"
#include "common.hpp"

static int buf_size = 2048;
static unsigned long long cipher_out_len = 0;
static std::vector<unsigned char> buffer(buf_size);
//for salsa20 and chacha20 and chacha20-ietf
static int BLOCK_SIZE = 64;

//for crypto_stream_chacha20_ietf_xor_ic 5th arg 
inline static int encap_crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, uint64_t ic, const unsigned char *k)
{
    return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, (uint32_t)ic, k); 
}

SodiumStreamCrypto::SodiumStreamCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, 
                                       const std::vector<unsigned char> &iv, const int op): _key(key), _iv(iv) 
{
    load_sodium();

    if (cipher_name == "salsa20")
        _cipher = crypto_stream_salsa20_xor_ic;

    else if (cipher_name == "chacha20")
        _cipher = crypto_stream_chacha20_xor_ic;

    else if (cipher_name == "xchacha20")
        _cipher = crypto_stream_xchacha20_xor_ic;
        
    else if (cipher_name == "chacha20-ietf")
        _cipher = encap_crypto_stream_chacha20_ietf_xor_ic;

    else
    {
        throw ExceptionInfo("libsodium: Unknown cipher" + cipher_name);
    }
}

void SodiumStreamCrypto::update(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    int padding = _counter % BLOCK_SIZE;
    int total_len = padding + in_len;
    std::vector<unsigned char> data;
    const unsigned char *data_ptr = in;

    if (buf_size < total_len)
    {
        buf_size = total_len * 2;
        buffer.resize(buf_size);
    }

    if (padding)
    {
        data.resize(padding, 0);
        std::copy(in, in + in_len, std::back_inserter(data));
        
        data_ptr = &data[0];
    }

    _cipher(&buffer[0], data_ptr, total_len, &_iv[0], _counter / BLOCK_SIZE, &_key[0]);
    
    _counter += in_len; //the max value is 2^64 - 1, may overflow.

    // strip off the padding
    std::copy(buffer.begin() + padding, buffer.begin() + total_len, std::back_inserter(out));
}

SodiumAeadCrypto::SodiumAeadCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, 
                                   const std::vector<unsigned char> &iv, const int op) : AeadCryptoBase(cipher_name, key, iv, op)
{
    if (cipher_name == "chacha20-poly1305")
    {
        _encryptor = crypto_aead_chacha20poly1305_encrypt;
        _decryptor = crypto_aead_chacha20poly1305_decrypt;
    }
    else if (cipher_name == "chacha20-ietf-poly1305")
    {
        _encryptor = crypto_aead_chacha20poly1305_ietf_encrypt;
        _decryptor = crypto_aead_chacha20poly1305_ietf_decrypt;
    }
    else if (cipher_name == "xchacha20-ietf-poly1305")
    {
        _encryptor = crypto_aead_xchacha20poly1305_ietf_encrypt;
        _decryptor = crypto_aead_xchacha20poly1305_ietf_decrypt;
    }
    else if (cipher_name == "sodium:aes-256-gcm")
    {
        if (!crypto_aead_aes256gcm_is_available())
        {
            throw ExceptionInfo("sodium:aes-256-gcm is not available on this CPU, please try ohter method");
        }
        _encryptor = crypto_aead_aes256gcm_encrypt;
        _decryptor = crypto_aead_aes256gcm_decrypt;
    }
    else
    {
        throw ExceptionInfo("libsodium: Unknown cipher: " + cipher_name);
    }
}

inline void SodiumAeadCrypto::cipher_ctx_init()
{
    nonce_increment();
}

void SodiumAeadCrypto::aead_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    cipher_out_len = 0;
    size_t total_len = in_len + _tlen;
    size_t out_size = out.size();
    if (buf_size < total_len)
    {
        buf_size = total_len * 2;
    } 
    
    out.resize(out_size + buf_size);
    _encryptor(&out[out_size], &cipher_out_len, in, in_len, nullptr, 0, nullptr, &_nonce[0], &_skey[0]);
    if (cipher_out_len != total_len)
    {
        throw SodiumError("libsodium: Encrypt failed");
    }
    cipher_ctx_init();
    out.resize(out_size + cipher_out_len);
}

void SodiumAeadCrypto::aead_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    cipher_out_len = 0;
    size_t out_size = out.size();
    if (buf_size < in_len)
    {
        buf_size = in_len * 2;
    } 

    out.resize(out_size + buf_size);
    if(_decryptor(&out[out_size], &cipher_out_len, nullptr, in, in_len, nullptr, 0, &_nonce[0], &_skey[0]) < 0)
    {
        throw SodiumError("libsodium: Decrypt failed");
    }
    if (cipher_out_len != in_len - _tlen)
    {
        throw SodiumError("libsodium: Decrypt failed");
    }
    cipher_ctx_init();
    out.resize(out_size + cipher_out_len);
}

