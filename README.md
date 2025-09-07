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
RFC3489 11.2.6 Username(不支持)  
RFC3489 11.2.7 Password(不支持,RFC5389弃用)  
RFC3489 11.2.8 Message-Integrity  
RFC3489 11.2.9 Error-Code  
RFC3489 11.2.10 Unknown-Attribute  
RFC3489 11.2.11 Reflected-From(RFC5389弃用)

## RFC5389
仅支持普通绑定请求。  
RFC5389 15.1 Mapped-Address  
RFC5389 15.2 XOR-Mapped-Address  
RFC5389 15.3 Username(不支持)  
RFC5389 15.4 Message-Integrity  
RFC5389 15.5 Fingerprint(不支持)  
RFC5389 15.6 Error-Code  
RFC5389 15.7 Realm(不支持)  
RFC5389 15.8 Nonce(不支持)  
RFC5389 15.9 Unknown-Attribute  
RFC5389 15.10 Sofeware(不支持)  
RFC5389 15.11 Alternate-Server(不支持)  

## RFC5780
RFC5780 7.2 Change-Request  
RFC5780 7.3 Response-Origin  
RFC5780 7.4 Other-Address  
RFC5780 7.5 Response-Port  
RFC5780 7.6 Padding(不支持)

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
  "PrimaryPort": 3478,//第一个端口号
  "SecondaryPort": 3479,//第二个端口号
  "TLSPrimaryPort": 5349,//第一个TLS端口号
  "TLSSecondaryPort": 5350,//第二个TLS端口号
  "LocalPrimaryIPv4Address": null,//本地第一个IPv4地址
  "LocalSecondaryIPv4Address": null,//本地第二个IPv4地址
  "LocalPrimaryPort": null,//本地第一个端口号
  "LocalSecondaryPort": null,//本地第二个端口号
  "LocalTLSPrimaryPort": null,//本地第一个TLS端口号
  "LocalTLSSecondaryPort": null,//本地第二个TLS端口号
  "EnableUDP": true,//是否启用UDP协议
  "EnableTCP": true,//是否启用TCP协议
  "EnableTLS": true,//是否启用TLS协议
  "CertificateFile": "tls.pem"//TLS证书文件路径（启用TLS协议时必填，且必须带有私钥）
}
```
Local开头的参数，一般用于处于内网环境，没有直接拥有公网IP地址的服务器使用。  
该参数用于进行Socket绑定，不影响返回给Stun客户端的服务器地址与端口号。

# 推荐Stun客户端
C#开发的网络NAT状态测试工具  
https://github.com/HMBSbige/NatTypeTester