#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include <arpa/inet.h>

#include <algorithm>
#include <iterator> 
#include <map>
#include <string>

#include <sodium.h>
#include <openssl/hmac.h>

#include "easylogging++.hpp"
#include "aead.hpp"
#include "common.hpp"

#define AEAD_MSG_LEN_UNKNOWN  0
#define AEAD_CHUNK_SIZE_LEN  2
#define AEAD_CHUNK_SIZE_MASK  0x3FFF


static std::map<std::string, int> CIPHER_NONCE_LEN = {
    {"aes-128-gcm", 12},
    {"aes-192-gcm", 12},
    {"aes-256-gcm", 12},
    {"aes-128-ocb", 12},   //requires openssl 1.1
    {"aes-192-ocb", 12},
    {"aes-256-ocb", 12},
    {"chacha20-poly1305", 12},
    {"chacha20-ietf-poly1305", 12},
    {"xchacha20-ietf-poly1305", 24},
    {"sodium:aes-256-gcm", 12}
};

static std::map<std::string, int> CIPHER_TAG_LEN = {
    {"aes-128-gcm", 16},
    {"aes-192-gcm", 16},
    {"aes-256-gcm", 16},
    {"aes-128-ocb", 16},   //requires openssl 1.1
    {"aes-192-ocb", 16},
    {"aes-256-ocb", 16},
    {"chacha20-poly1305", 16},
    {"chacha20-ietf-poly1305", 16},
    {"xchacha20-ietf-poly1305", 16},
    {"sodium:aes-256-gcm", 16}
};

const static std::vector<unsigned char> SUBKEY_INFO = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
static bool sodium_loaded = false;


void load_sodium()
{
    if (sodium_loaded)
        return;
    
    if (sodium_init() == -1) 
    {
        throw ExceptionInfo("init sodium error");
    }
    
    int fd;
    int c;

    if ((fd = open("/dev/random", O_RDONLY)) != -1) 
    {
        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) 
        {
            LOG(ERROR) << "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                       << "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                       << "On virtualized Linux environments, also consider using virtio-rng.\n"
                       << "The service will not start until enough entropy has been collected.\n";
            throw ExceptionInfo("/dev/random error");
        }
        close(fd);
    }
    else 
    {
        throw SysError("can not open /dev/random: " + get_std_error_str());
    }
    
    sodium_loaded = true;
}
    

static void hkdf_extract(std::vector<unsigned char> &salt, const std::vector<unsigned char> &input_key_material, 
                         const EVP_MD *algorithm, std::vector<unsigned char> &out)
{
    unsigned int out_size = 0;
    if (salt.empty())
        salt.resize(EVP_MD_size(algorithm));
    out.resize(EVP_MD_size(algorithm));

    if (!HMAC(algorithm, &salt[0], salt.size(), &input_key_material[0], input_key_material.size(), &out[0], &out_size))
    {
        throw OpensslError("HMAC error: " + get_opensll_error_str());
    }
    if (out_size != EVP_MD_size(algorithm))
    {
        throw OpensslError("HMAC output length invaild");
    }
}

static void hkdf_expand(const std::vector<unsigned char> &pseudo_random_key, const std::vector<unsigned char> &info, const int length, 
                        const EVP_MD *algorithm, std::vector<unsigned char> &out)
{
    int hash_len = EVP_MD_size(algorithm);
    if (length > 255 * hash_len)
    {
        LOG(ERROR) << "Cannot expand to more than 255 * " << hash_len 
        << " = " << 255 * hash_len
        << " bytes using the specified hash function";
        throw OpensslError("hkdf_expand: key length invaild");                  
    }
    
    int blocks_needed = length / hash_len + ((length % hash_len == 0) ? 0 : 1);

    std::vector<unsigned char> output_block; 
    std::vector<unsigned char> in;
    output_block.resize(EVP_MD_size(algorithm));
    
    out.clear();
    for (int counter = 0; counter < blocks_needed; counter++)
    {   
        if (counter)
            in = output_block;
        
        std::copy(info.cbegin(), info.cend(), std::back_inserter(in));
        in.push_back(counter + 1);
                
        if (!HMAC(algorithm, &pseudo_random_key[0], pseudo_random_key.size(), 
                   &in[0], in.size(), &output_block[0], nullptr))
        {
            throw OpensslError("HMAC error: " + get_opensll_error_str());
        }
                     
        std::copy(output_block.cbegin(), output_block.cend(), std::back_inserter(out));     
    }
    
    out.resize(length);
}

static void key_hkdf_expand(std::vector<unsigned char> &salt,  const std::vector<unsigned char > &info, const std::vector<unsigned char> &key, const EVP_MD *algorithm, 
                            std::vector<unsigned char> &out)
{
    std::vector<unsigned char> prk;
    hkdf_extract(salt, key, algorithm, prk);
    hkdf_expand(prk, info, key.size(), algorithm, out); 
}


/*  
Handles basic aead process of shadowsocks protocol

TCP Chunk (after encryption, *ciphertext*)
+--------------+---------------+--------------+------------+
|  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
+--------------+---------------+--------------+------------+
|      2       |     Fixed     |   Variable   |   Fixed    |
+--------------+---------------+--------------+------------+

UDP (after encryption, *ciphertext*)
+--------+-----------+-----------+
| NONCE  |  *Data*   |  Data_TAG |
+-------+-----------+-----------+
| Fixed  | Variable  |   Fixed   |
+--------+-----------+-----------+
*/

AeadCryptoBase::AeadCryptoBase(const std::string &cipher_name, const std::vector<unsigned char> &key,  std::vector<unsigned char> iv, 
                               const int op)
{
    _op = op;
    _nlen = CIPHER_NONCE_LEN[cipher_name]; 
    _nonce.resize(_nlen, 0); 
    _tlen = CIPHER_TAG_LEN[cipher_name]; 
    key_hkdf_expand(iv, SUBKEY_INFO, key, EVP_sha1(), _skey);
    load_sodium();
}

//sodium_increment(byref(self._nonce), c_int(self._nlen))

void AeadCryptoBase::nonce_increment()
{
    sodium_increment(&_nonce[0], _nlen);
}            

void AeadCryptoBase::encrypt_chunk(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{  
    unsigned short int net_order_plen = htons(in_len & AEAD_CHUNK_SIZE_MASK);
    size_t out_szie = out.size();

    aead_encrypt((unsigned char *)&net_order_plen, sizeof(net_order_plen), out);   
    if (out.size() - out_szie != AEAD_CHUNK_SIZE_LEN + _tlen)
    {
        throw ExceptionInfo("encrypt_chunk:size length invalid");
    }
    
    out_szie = out.size();
    aead_encrypt(in, in_len, out);

    if (out.size() - out_szie != in_len + _tlen)
    {
        throw ExceptionInfo("encrypt_chunk:data length invalid");
    }
}

void AeadCryptoBase::aead_base_encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    if (in_len <= AEAD_CHUNK_SIZE_MASK)
    {
        return encrypt_chunk(in, in_len, out);
    }
    
    int plen = in_len;
    while (plen > 0)
    {
        int mlen = plen < AEAD_CHUNK_SIZE_MASK ? plen : AEAD_CHUNK_SIZE_MASK;       
        encrypt_chunk(in, mlen, out);      
        in += mlen; 
        plen -= mlen;  
    }
}

void AeadCryptoBase::decrypt_chunk_size()
{
    int hlen = AEAD_CHUNK_SIZE_LEN + _tlen;
    std::vector<unsigned char> plen_out;
    aead_decrypt(&_chunk_data[_chunk_data_pos], hlen, plen_out);//input DataLen +  DataLen's tag
    
    //DataLen
    unsigned short int *plen = (unsigned short int *)&plen_out[0];
    unsigned short int host_order_plen = ntohs(*plen);
   
    if ((host_order_plen & AEAD_CHUNK_SIZE_MASK) != host_order_plen || host_order_plen <= 0)
    {
        throw ExceptionInfo("decrypt_chunk_size: Invalid message length");
    }
    
    _chunk_payload_len = host_order_plen; //next encrypted data length
    _chunk_data_pos += hlen; //the position of Data + Data_TAG
}

void AeadCryptoBase::decrypt_chunk_payload(std::vector<unsigned char> &out)
{
    size_t out_size = out.size();
    aead_decrypt(&_chunk_data[_chunk_data_pos], _chunk_payload_len + _tlen, out);
    if (out.size() - out_size != _chunk_payload_len)
    {
        throw ExceptionInfo("decrypt_chunk_payload: Plaintext length invalid");
    }
    _chunk_data_pos += _chunk_payload_len + _tlen; //the position of DataLen + DataLen_TAG
    _chunk_payload_len = 0; //reset the next encrypted data length
}

bool AeadCryptoBase::is_chunk_data_available()
{
    auto tag_size = AEAD_CHUNK_SIZE_LEN + _tlen;
    auto data_size = _chunk_payload_len + _tlen;
    if ((_chunk_payload_len == 0) && (_chunk_data.size() - _chunk_data_pos >= tag_size))
        return true;
        
    if((_chunk_payload_len > 0) && (_chunk_data.size() - _chunk_data_pos >= data_size))
        return true;
    
    return false;
}

void AeadCryptoBase::aead_base_decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out)
{
    std::copy(in, in + in_len, std::back_inserter(_chunk_data));
    
    while (is_chunk_data_available())
    {        
        if (_chunk_payload_len == 0)
        {
            decrypt_chunk_size();
            continue;
        }
        
        if (_chunk_payload_len > 0)
        {
            decrypt_chunk_payload(out);  
        }
    }
    
    std::copy(_chunk_data.begin() + _chunk_data_pos, _chunk_data.end(), _chunk_data.begin());
    _chunk_data.resize(_chunk_data.size() - _chunk_data_pos);
    _chunk_data_pos = 0;
}