# shadowsocksR

[shadowsocksR](https://github.com/v2rayA/shadowsocksR) is a shadowsocksR library for Go

* shadowsocksR is based on [avege](https://github.com/avege/avege) and [other shadowsocksR projects](#Credits). 
* Some problems of [the previous project](https://github.com/sun8911879/shadowsocksR) have been fixed, and new protocols are added.

#### Use

See 'example/main.go' for detailed usage.

#### SS Encrypting algorithm

*Not support AEAD method yet.*

* aes-128-cfb
* aes-192-cfb
* aes-256-cfb
* aes-128-ctr
* aes-192-ctr
* aes-256-ctr
* aes-128-ofb
* aes-192-ofb
* aes-256-ofb
* des-cfb
* bf-cfb
* cast5-cfb
* rc4-md5
* chacha20
* chacha20-ietf
* salsa20
* camellia-128-cfb
* camellia-192-cfb
* camellia-256-cfb
* idea-cfb
* rc2-cfb
* seed-cfb
* none

#### SSR Obfs

- plain
- http_simple
- http_post
- random_head
- tls1.2_ticket_auth

#### SSR Protocol

- origin
- verify_sha1 aka. one time auth(OTA)
- auth_sha1_v4
- auth_aes128_md5
- auth_aes128_sha1
- auth_chain_a
- auth_chain_b

### Credits
* [avege](https://github.com/avege/avege)
* [ShadowsocksR](https://github.com/shadowsocksrr/shadowsocksr)
* [shadowsocksr-libev](https://github.com/shadowsocksr-backup/shadowsocksr-libev)
