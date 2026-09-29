# Wodsoft.StunServer 
一个使用C#语言的Stun服务器。

# 支持协议

## RFC3489
仅支持普通绑定请求。  
RFC3489 11.2.1 Mapped-Address  
RFC3489 11.2.2 Response-Address(RFC5389弃用)  
RFC3489 11.2.3 Changed-Address(RFC5389弃用)  
RFC3489 11.2.4 Change-Request(RFC5389弃用,RFC5780重新启用)  
RFC3489 11.2.5 Source-Address(RFC5389弃用)  
RFC3489 11.2.6 Username  
RFC3489 11.2.7 Password(不支持,RFC5389弃用)  
RFC3489 11.2.8 Message-Integrity  
RFC3489 11.2.9 Error-Code  
RFC3489 11.2.10 Unknown-Attribute  
RFC3489 11.2.11 Reflected-From(RFC5389弃用)

## RFC5389
仅支持普通绑定请求。  
RFC5389 15.1 Mapped-Address  
RFC5389 15.2 XOR-Mapped-Address  
RFC5389 15.3 Username  
RFC5389 15.4 Message-Integrity  
RFC5389 15.5 Fingerprint(不支持)  
RFC5389 15.6 Error-Code  
RFC5389 15.7 Realm  
RFC5389 15.8 Nonce  
RFC5389 15.9 Unknown-Attribute  
RFC5389 15.10 Software(不支持)  
RFC5389 15.11 Alternate-Server(不支持)  

## RFC5780
RFC5780 7.2 Change-Request  
RFC5780 7.3 Response-Origin  
RFC5780 7.4 Other-Address  
RFC5780 7.5 Response-Port  
RFC5780 7.6 Padding(不支持)

## RFC8489
RFC8489 14.6 MESSAGE-INTEGRITY-SHA256  
RFC8489 14.11 PASSWORD-ALGORITHM  
RFC8489 14.12 PASSWORD-ALGORITHMS  

## 认证
默认不强制认证。子类可通过 `RequireAuthorized` / `AuthorizationRealm` / `GetPasswordAsync` 启用：  
- 短期凭证：USERNAME + MESSAGE-INTEGRITY（或 MESSAGE-INTEGRITY-SHA256）  
- 长期凭证：USERNAME + REALM + NONCE + MESSAGE-INTEGRITY（或 MESSAGE-INTEGRITY-SHA256）；挑战响应会返回 REALM、NONCE、PASSWORD-ALGORITHMS（MD5 / SHA-256）  
- 支持错误码 401 Unauthorized、438 Stale Nonce、420 Unknown Attribute、400 Bad Request

# 如何使用

## 配置

### 初始化配置文件
```
stunserver config generate
```
此命令会初始化config.json配置文件。

### 验证配置文件
```
stunserver config validate
```
此命令会验证config.json配置文件的正确性。

## 运行
```
stunserver run
```
此命令会启动Stun服务器

### 可选参数
```
-v LogLevel
```
- Trace
- Debug
- **Information**  (默认)
- Warning
- Error

# 配置文件说明
```
{
  "PrimaryIPv4Address": "",//第一个IPv4地址
  "SecondaryIPv4Address": "",//第二个IPv4地址
  "PrimaryIPv6Address": "",//第一个IPv6地址
  "SecondaryIPv6Address": "",//第二个IPv6地址
  "PrimaryPort": 3478,//第一个端口号
  "SecondaryPort": 3479,//第二个端口号
  "TLSPrimaryPort": 5349,//第一个TLS端口号
  "TLSSecondaryPort": 5350,//第二个TLS端口号
  "LocalPrimaryIPv4Address": null,//本地第一个IPv4地址
  "LocalSecondaryIPv4Address": null,//本地第二个IPv4地址
  "LocalPrimaryIPv6Address": null,//本地第一个IPv6地址
  "LocalSecondaryIPv6Address": null,//本地第二个IPv6地址
  "LocalPrimaryPort": null,//本地第一个端口号
  "LocalSecondaryPort": null,//本地第二个端口号
  "LocalTLSPrimaryPort": null,//本地第一个TLS端口号
  "LocalTLSSecondaryPort": null,//本地第二个TLS端口号
  "ProxyLocalIPv4Address": null,//UDP Proxy本地IPv4地址（本机绑定）
  "ProxyRemoteIPv4Address": null,//UDP Proxy对端IPv4地址
  "ProxyLocalIPv4Port": 51200,//UDP Proxy本地IPv4端口
  "ProxyRemoteIPv4Port": 51200,//UDP Proxy对端IPv4端口
  "ProxyLocalIPv6Address": null,//UDP Proxy本地IPv6地址（本机绑定）
  "ProxyRemoteIPv6Address": null,//UDP Proxy对端IPv6地址
  "ProxyLocalIPv6Port": 51201,//UDP Proxy本地IPv6端口
  "ProxyRemoteIPv6Port": 51201,//UDP Proxy对端IPv6端口
  "EnableUDP": true,//是否启用UDP协议
  "EnableUDPProxy": false,//是否启用双机UDP Proxy模式
  "EnableTCP": false,//是否启用TCP协议
  "EnableTLS": false,//是否启用TLS协议
  "EnableIPv4": true,//是否启用IPv4
  "EnableIPv6": false,//是否启用IPv6
  "CertificateFile": "tls.pem"//TLS证书文件路径（启用TLS协议时必填，且必须带有私钥）
}
```
Local开头的参数，一般用于处于内网环境，没有直接拥有公网IP地址的服务器使用。  
该参数用于进行Socket绑定，不影响返回给Stun客户端的服务器地址与端口号。

# 双机组成 Stun over UDP

完整的 STUN UDP 服务通常需要同一主机绑定两个公网地址（Primary / Secondary），才能正确响应 Change-Request 等行为。  
当两台机器各自只有一个公网地址时，可开启 `EnableUDPProxy`，通过私有 UDP Proxy 通道互相转发“另一地址”的响应，共同组成一套 Stun over UDP 服务。

## 工作原理

- 每台机器只在本机 Primary 地址上绑定 PrimaryPort / SecondaryPort，对外提供 STUN 服务。
- 需要从 Secondary 地址发出的响应，会经本机 Proxy Socket 附加客户端地址与端口标记后，发往对端 `ProxyRemote`。
- 对端收到 Proxy 报文后，再从本机对应端口发给客户端，从而实现跨机器的“换地址 / 换端口”响应。
- Proxy 通道仅用于两台服务器之间通信，不对 STUN 客户端开放。

## 部署要求

1. 两台机器分别拥有一个公网地址，且均可被客户端访问 PrimaryPort / SecondaryPort。
2. 两台机器之间网络互通，可互相访问对方的 Proxy 端口（默认 IPv4: 51200，IPv6: 51201）。
3. 两台机器均启用 `EnableUDP` + `EnableUDPProxy`，对外公布的 Primary / Secondary 地址互相交叉配置。
4. 当前仅支持 UDP；TCP / TLS 仍按单机 Primary 地址工作。

## 配置示例（IPv4）

假设：
- 机器 A 公网地址：`1.1.1.1`
- 机器 B 公网地址：`2.2.2.2`
- 内网互通地址分别为 `10.0.0.1` / `10.0.0.2`

### 机器 A（config.json）
```
{
  "PrimaryIPv4Address": "1.1.1.1",
  "SecondaryIPv4Address": "2.2.2.2",
  "PrimaryPort": 3478,
  "SecondaryPort": 3479,
  "EnableUDP": true,
  "EnableUDPProxy": true,
  "EnableTCP": false,
  "EnableTLS": false,
  "EnableIPv4": true,
  "EnableIPv6": false,
  "ProxyLocalIPv4Address": "10.0.0.1",
  "ProxyLocalIPv4Port": 51200,
  "ProxyRemoteIPv4Address": "10.0.0.2",
  "ProxyRemoteIPv4Port": 51200
}
```

### 机器 B（config.json）
```
{
  "PrimaryIPv4Address": "2.2.2.2",
  "SecondaryIPv4Address": "1.1.1.1",
  "PrimaryPort": 3478,
  "SecondaryPort": 3479,
  "EnableUDP": true,
  "EnableUDPProxy": true,
  "EnableTCP": false,
  "EnableTLS": false,
  "EnableIPv4": true,
  "EnableIPv6": false,
  "ProxyLocalIPv4Address": "10.0.0.2",
  "ProxyLocalIPv4Port": 51200,
  "ProxyRemoteIPv4Address": "10.0.0.1",
  "ProxyRemoteIPv4Port": 51200
}
```

要点：
- 机器 A 的 Primary 对应机器 B 的 Secondary，反之亦然。
- `ProxyLocal*` 为本机 Proxy Socket 绑定地址/端口；`ProxyRemote*` 为对端 Proxy 地址/端口。
- 若服务器直接使用公网地址互通，`ProxyLocal*` / `ProxyRemote*` 也可直接填写对应公网地址。
- 启用 IPv6 时，按同样规则配置 `ProxyLocalIPv6*` / `ProxyRemoteIPv6*`（默认端口 51201）。

# 推荐Stun客户端
C#开发的网络NAT状态测试工具  
https://github.com/HMBSbige/NatTypeTester