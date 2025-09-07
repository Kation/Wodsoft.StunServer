# Wodsoft.StunServer 
һ��ʹ��C#���Ե�Stun��������

# ֧��Э��

## RFC3489
��֧����ͨ������  
RFC3489 11.2.2 ResponseAddress  
RFC3489 11.2.3 ChangeRequest  
RFC3489 11.2.8 MessageIntegrity  

## RFC5389
��֧����ͨ������  
RFC3489 11.2.2 ResponseAddress  
RFC3489 11.2.3 ChangeRequest  
RFC5389 15.4 MessageIntegrity  

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