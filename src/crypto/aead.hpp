#ifndef AEAD_HPP
#define AEAD_HPP

#include <vector>

#include "cryptor.hpp"

void load_sodium();

class AeadCryptoBase
{
public:
    AeadCryptoBase() = default;
    AeadCryptoBase(const std::string &cipher_name, const std::vector<unsigned char> &key, std::vector<unsigned char> iv, const int op);
    AeadCryptoBase(const AeadCryptoBase &base) = delete;
    AeadCryptoBase& operator =(const AeadCryptoBase &base) = delete;
    virtual ~AeadCryptoBase() {}

private:
    void encrypt_chunk(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
    void decrypt_chunk_size();
    void decrypt_chunk_payload(std::vector<unsigned char> &out);
    bool is_chunk_data_available();
    
    unsigned int _chunk_payload_len = 0;
    unsigned int _chunk_data_pos = 0;
    std::vector<unsigned char> _chunk_data;
    
protected:
    int _op = -1;
    unsigned int _nlen; 
    unsigned int _tlen; 
    std::vector<unsigned char> _nonce; 
    std::vector<unsigned char> _skey;

    void nonce_increment();
    void aead_base_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
    void aead_base_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out); 
    virtual void aead_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
    virtual void aead_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
};



#endif