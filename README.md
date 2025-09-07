# Wodsoft.StunServer 
一个使用C#语言的Stun服务器。

# 支持协议

## RFC3489
仅支持普通绑定请求。  
RFC3489 11.2.2 ResponseAddress  
RFC3489 11.2.3 ChangeRequest  
RFC3489 11.2.8 MessageIntegrity  

## RFC5389
仅支持普通绑定请求。  
RFC3489 11.2.2 ResponseAddress  
RFC3489 11.2.3 ChangeRequest  
RFC5389 15.4 MessageIntegrity  

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