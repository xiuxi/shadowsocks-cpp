Shadowsocks-cpp
===============

### Introduction

Shadowsocks-cpp is written in c++ according to the [Shadowsocks](https://github.com/shadowsocks/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy), you can visit [shadowsocks.org](https://www.shadowsocks.org/en/) 
website for more detail introduction.

### Install

May install opensll or libsodium

```bash
git clone https://github.com/maywine/shadowsocks-cpp.git
cd shadowsocks-cpp
chmod +x install.py
sudo ./install.py
``` 

### Usage

```bash
ssc++
    -c, --config             path to config file, default: null
    -p, --server_port        server port, default: 8388
    -s, --server             server address, default: 0.0.0.0
    -k, --password           password, default: null
    -m, --method             encryption method, default: xchacha20-ietf-poly1305
                             Sodium:
                                 chacha20-poly1305, chacha20-ietf-poly1305,
                                 xchacha20-ietf-poly1305, sodium:aes-256-gcm,
                                 salsa20, chacha20, chacha20-ietf, xchacha20
                             OpenSSL:
                                 aes-{128|192|256}-gcm, aes-{128|192|256}-cfb,
                                 aes-{128|192|256}-ofb, aes-{128|192|256}-ctr,
                                 aes-{128|192|256}-ocb, camellia-{128|192|256}-cfb,
                                 des-cfb, idea-cfb, rc2-cfb, seed-cfb, rc4,
                                 rc4-md5, table, bf-cfb, cast5-cfb
    -a, --one_time_auth      one time auth
    -t, --timeout            timeout in seconds, default: 300
        --fast_open          use TCP_FASTOPEN, requires Linux 3.7+
        --workers            number of progress to run, default: 1
        --manager_address    optional server manager UDP address, see wiki
        --user               username to run as
        --forbidden_ip       comma seperated IP list forbidden to connect, default: 127.0.0.0/8,::1/128
    -d, --daemon             daemon mode: start/stop/restart, default: null
        --pid_file           pid file for daemon mode, default: /var/run/shadowsocksc++.pid
        --log_file           pid file for daemon mode, default: /var/log/shadowsocksc++.log
    -q, --quiet              quiet mode, only show warnings/info
    -v, --verbose            verbose mode, show more information
        --prefer_ipv6        resolve ipv6 address first
        --version            show version information
    -?, --help               print this message            
```
### Config File

Shadowsocks accepts JSON format configs like this:

```bash
{
    "server":"my_server_ip",
    "server_port":8388,
    "password":"barfoo!",
    "timeout":300,
    "method":"xchacha20-ietf-poly1305"
}
```

Explanation of each field:

```bash
server: your hostname or server IP (IPv4/IPv6).
server_port: server port number.
password: a password used to encrypt transfer.
timeout: connections timeout in seconds.
method: encryption method.
```
For more detail, see [shadowsocks.org](https://www.shadowsocks.org/en/config/quick-guide.html) guide.

#### License

[LICENSE]

#### Open Source Components / Libraries

```bash
Shadowsocks (Apache 2.0)    https://github.com/shadowsocks/shadowsocks
Cmdline                     https://github.com/tanakh/cmdline
Easylogging++ (MIT)         https://github.com/muflihun/easyloggingpp
json (MIT)                  https://github.com/nlohmann/json
Openssl                     https://github.com/openssl/openssl
Libsodium(ISC)              https://github.com/jedisct1/libsodium
```


[LICENSE]:        https://github.com/maywine/shadowsocks-cpp/blob/master/LICENSE



