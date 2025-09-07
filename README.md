# Wodsoft.StunServer 
һ��ʹ��C#���Ե�Stun��������

# ֧��Э��

## RFC3489
��֧����ͨ������  
RFC3489 11.2.1 Mapped-Address  
RFC3489 11.2.2 Response-Address(RFC5389����)  
RFC3489 11.2.3 Changed-Address(RFC5389����)  
RFC3489 11.2.4 Change-Request(RFC5389����,RFC5780��������)  
RFC3489 11.2.5 Source-Address(RFC5389����)  
RFC3489 11.2.6 Username(��֧��)  
RFC3489 11.2.7 Password(��֧��,RFC5389����)  
RFC3489 11.2.8 Message-Integrity  
RFC3489 11.2.9 Error-Code  
RFC3489 11.2.10 Unknown-Attribute  
RFC3489 11.2.11 Reflected-From(RFC5389����)

## RFC5389
��֧����ͨ������  
RFC5389 15.1 Mapped-Address  
RFC5389 15.2 XOR-Mapped-Address  
RFC5389 15.3 Username(��֧��)  
RFC5389 15.4 Message-Integrity  
RFC5389 15.5 Fingerprint(��֧��)  
RFC5389 15.6 Error-Code  
RFC5389 15.7 Realm(��֧��)  
RFC5389 15.8 Nonce(��֧��)  
RFC5389 15.9 Unknown-Attribute  
RFC5389 15.10 Sofeware(��֧��)  
RFC5389 15.11 Alternate-Server(��֧��)  

## RFC5780
RFC5780 7.2 Change-Request  
RFC5780 7.3 Response-Origin  
RFC5780 7.4 Other-Address  
RFC5780 7.5 Response-Port  
RFC5780 7.6 Padding(��֧��)

# ���ʹ��

## ����

### ��ʼ�������ļ�
```
stunserver config generate
```
��������ʼ��config.json�����ļ���

### ��֤�����ļ�
```
stunserver config validate
```
���������֤config.json�����ļ�����ȷ�ԡ�

## ����
```
stunserver run
```
�����������Stun������

### ��ѡ����
```
-v LogLevel
```
- Trace
- Debug
- **Information**  (Ĭ��)
- Warning
- Error

# �����ļ�˵��
```
{
  "PrimaryIPv4Address": "",//��һ��IPv4��ַ
  "SecondaryIPv4Address": "",//�ڶ���IPv4��ַ
  "PrimaryPort": 3478,//��һ���˿ں�
  "SecondaryPort": 3479,//�ڶ����˿ں�
  "TLSPrimaryPort": 5349,//��һ��TLS�˿ں�
  "TLSSecondaryPort": 5350,//�ڶ���TLS�˿ں�
  "LocalPrimaryIPv4Address": null,//���ص�һ��IPv4��ַ
  "LocalSecondaryIPv4Address": null,//���صڶ���IPv4��ַ
  "LocalPrimaryPort": null,//���ص�һ���˿ں�
  "LocalSecondaryPort": null,//���صڶ����˿ں�
  "LocalTLSPrimaryPort": null,//���ص�һ��TLS�˿ں�
  "LocalTLSSecondaryPort": null,//���صڶ���TLS�˿ں�
  "EnableUDP": true,//�Ƿ�����UDPЭ��
  "EnableTCP": true,//�Ƿ�����TCPЭ��
  "EnableTLS": true,//�Ƿ�����TLSЭ��
  "CertificateFile": "tls.pem"//TLS֤���ļ�·��������TLSЭ��ʱ����ұ������˽Կ��
}
```
Local��ͷ�Ĳ�����һ�����ڴ�������������û��ֱ��ӵ�й���IP��ַ�ķ�����ʹ�á�  
�ò������ڽ���Socket�󶨣���Ӱ�췵�ظ�Stun�ͻ��˵ķ�������ַ��˿ںš�

# �Ƽ�Stun�ͻ���
C#����������NAT״̬���Թ���  
https://github.com/HMBSbige/NatTypeTester