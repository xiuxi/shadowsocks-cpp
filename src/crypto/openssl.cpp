#include <openssl/evp.h>
#include "openssl.hpp"
#include "common.hpp"

static unsigned int buf_size = 2048;
static int out_length = 0;

OpenSSLCryptoBase::OpenSSLCryptoBase(const std::string &cipher_name)
{
    _cipher = EVP_get_cipherbyname(cipher_name.c_str());
    if (!_cipher)
    {
        throw OpensslError("cipher not found in libopenssl: " + get_opensll_error_str()); 
    }
    
    _ctx = EVP_CIPHER_CTX_new();
    if (!_ctx)
    {
        throw OpensslError("can not create cipher contex: " + get_opensll_error_str()); 
    }
}

void OpenSSLCryptoBase::update(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    out_length = 0; 
    size_t out_size = out.size();
    if (buf_size < in_len)
        buf_size = in_len * 2;
    
    out.resize(out_size + buf_size);
    if (!EVP_CipherUpdate(_ctx, &out[out_size], &out_length, in, in_len))
    {
        throw OpensslError("EVP_CipherUpdate error: " + get_opensll_error_str()); 
    }
    out.resize(out_size + out_length);    
}


void OpenSSLCryptoBase::_destroy()
{
    if (_ctx)
    {
        EVP_CIPHER_CTX_free(_ctx);
        _ctx = nullptr;
    }        
}

OpenSSLStreamCrypto::OpenSSLStreamCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, 
                                         const std::vector<unsigned char> &iv, const int op) 
                                         : OpenSSLCryptoBase(cipher_name)
{
    if (!EVP_CipherInit_ex(_ctx, _cipher, nullptr, &key[0], &iv[0], op))
    {   
        throw OpensslError("can not initialize cipher context: " + get_opensll_error_str());
    }
        
}

OpenSSLAeadCrypto::OpenSSLAeadCrypto(const std::string &cipher_name, const std::vector<unsigned char> &key, 
                                     const std::vector<unsigned char> &iv,  const int op): 
                                     OpenSSLCryptoBase(cipher_name), AeadCryptoBase(cipher_name, key, iv, op)
{
    if (!EVP_CipherInit_ex(_ctx, _cipher, nullptr, &_skey[0], nullptr, op))
    {
        throw OpensslError("can not initialize cipher context: " + get_opensll_error_str());
    }

    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_IVLEN, _nlen, nullptr))
    { 
        throw OpensslError("set ivlen failed");
    }
    cipher_ctx_init();
}

void OpenSSLAeadCrypto::cipher_ctx_init()
{  
    if (!EVP_CipherInit_ex(_ctx, nullptr, nullptr, nullptr, &_nonce[0], CIPHER_ENC_UNCHANGED))
    {
        throw OpensslError("can not initialize cipher context: " + get_opensll_error_str()); 
    }
    nonce_increment();
}

void  OpenSSLAeadCrypto::set_tag(const unsigned char *tag)
{
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_SET_TAG, _tlen, const_cast<unsigned char *>(tag)))
    {
        throw OpensslError("set tag failed: " + get_opensll_error_str());
    }
}

void OpenSSLAeadCrypto::get_tag(std::vector<unsigned char> &tag_buf)
{
    //Get authenticated tag, called after EVP_CipherFinal_ex
    size_t tag_size = tag_buf.size();
    tag_buf.resize(tag_size + _tlen);
    if(!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_AEAD_GET_TAG, _tlen, &tag_buf[tag_size]))
    {
        throw OpensslError("get tag failed: " + get_opensll_error_str());
    }
}

void OpenSSLAeadCrypto::cipher_final(std::vector<unsigned char> &out)
{
    out_length = 0;
    size_t out_size = out.size();
    out.resize(out_size + buf_size);
    
    if (!EVP_CipherFinal_ex(_ctx, &out[out_size], &out_length))
    {
        throw OpensslError("finalize cipher failed: " + get_opensll_error_str());
    }
    out.resize(out_size + out_length);
}

void OpenSSLAeadCrypto::aead_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    update(in, in_len, out);
    cipher_final(out);
    get_tag(out);
    cipher_ctx_init();
}

void OpenSSLAeadCrypto::aead_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    if (in_len < _tlen)
    {
        throw ExceptionInfo("Data too short");
    }

    set_tag(in + (in_len - _tlen)); //tag data
    update(in, in_len - _tlen, out);//decrypt data
    cipher_final(out);
    cipher_ctx_init();
}




