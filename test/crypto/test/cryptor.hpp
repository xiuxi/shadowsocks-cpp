#ifndef CRYPTOR_HPP
#define CRYPTOR_HPP

#include <string>
#include <memory>
#include <vector>

#define KEY_IV_M  std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, InfoMethod>
#define CIPHER_ENC_UNCHANGED -1
#define CIPHER_ENC_DECRYPTION 0
#define CIPHER_ENC_ENCRYPTION 1

enum class MethodLibs {NONE, OPENSSL, OPENSSL_AEAD, SODIUM, SODIUM_AEAD};

void decrypt_all(const std::string &password, const std::string &method, const unsigned char *data, const size_t data_len, 
                 std::vector<unsigned char> &out, std::vector<unsigned char> &key, std::vector<unsigned char> &iv);

void decrypt_all(const std::string &password, const std::string &method, const std::vector<unsigned char> &data, std::vector<unsigned char> &out,
                 std::vector<unsigned char> &key, std::vector<unsigned char> &iv);

void encrypt_all(const std::string &password, const std::string &method, const unsigned char *data, const size_t data_len, std::vector<unsigned char> &out);
void encrypt_all(const std::string &password, const std::string &method, const std::vector<unsigned char> &data, std::vector<unsigned char> &out);


void try_cipher(const std::string &key, const std::string &method);

struct InfoMethod
{
    InfoMethod() = default;
    InfoMethod(const std::string &method, const MethodLibs m_lib = MethodLibs::NONE, const int key_len = 0, const int iv_len = 0) :
               _method(method), _method_lib(m_lib), _key_len(key_len), _iv_len(iv_len){}
    bool operator <(const InfoMethod &m) const { return _method < m._method; }
    std::string _method;
    MethodLibs _method_lib = MethodLibs::NONE;
    int _key_len = 0;
    int _iv_len = 0;
};

class CryptorBase
{
public: 
    CryptorBase() = default;
    CryptorBase(const CryptorBase &base) = delete;
    CryptorBase& operator =(const CryptorBase &base) = delete;
    virtual ~CryptorBase(){};
    
    virtual void encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
    virtual void decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
    
    virtual void encrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
    virtual void decrypt_once(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out) = 0;
};  

class Cryptor
{
public:
    Cryptor() = default;
    Cryptor(const std::string &password, const std::string &method);
    Cryptor(const Cryptor &cryptor) = delete;
    Cryptor& operator =(const Cryptor &cryptor) = delete;
    ~Cryptor() = default;
    
    void encrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
    void decrypt(const unsigned char *in, const size_t in_len, std::vector<unsigned char> &out);
    void encrypt(const std::vector<unsigned char> &in, std::vector<unsigned char> &out)
    {
        encrypt(&in[0], in.size(), out);
    }
    void decrypt(const std::vector<unsigned char> &in, std::vector<unsigned char> &out)
    {
        decrypt(&in[0], in.size(), out);
    }

    const std::vector<unsigned char>& get_key() const { return _key; } 
    const std::vector<unsigned char>& get_cipher_iv() const { return _cipher_iv; } 
    const std::vector<unsigned char>& get_decipher_iv() const { return _decipher_iv; }
    
private:
    bool _iv_sent = false;
    std::vector<unsigned char> _key;
    InfoMethod _method;

    std::vector<unsigned char> _cipher_iv;
    std::shared_ptr<CryptorBase> _cipher;

    std::vector<unsigned char> _decipher_iv;
    std::shared_ptr<CryptorBase> _decipher;    
};

const InfoMethod get_method(const std::string &method);

#endif