# TLS13

   Figure 1 below shows the basic full TLS handshake:
```bash
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

               Figure 1: Message Flow for Full TLS Handshake
```
包含三个阶段：
* Key Exchange: 选择TLS密码学参数，生成shared keying material（ECDHE），这个阶段之后的消息都是加密的
* Server Parameters: 交换其他的一些握手信息
* Authentication: 认证server，提供握手的完整性

## 1 Key Exchange Messages
   The key exchange messages are used to determine the security
   capabilities of the client and the server and to establish shared
   secrets, including the traffic keys used to protect the rest of the
   handshake and the data.
### (1) Cryptographic Negotiation(可选)
Server发送给Client，包含：
* cipher suite list （AEAD/HKDF）
* supported groups for ECDHE or "key_share" extension
* signature algorithms extension
* pre_shared key extention

### (2) Client Hello
包含：
* 支持的TLS协议版本
* **随机数：这个值非常有用，生成预备主密钥的时候，在使用 PRF 算法计算导出主密钥和密钥块的时候，校验完整的消息都会用到，随机数主要是避免重放攻击。**
* session ID，主要用于会话恢复
* cipher suite支持列表
* Extension

SPEC定义：  
```bash
      uint16 ProtocolVersion;
      opaque Random[32];

      uint8 CipherSuite[2];    /* Cryptographic suite selector */

      struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id<0..32>;
          CipherSuite cipher_suites<2..2^16-2>;
          opaque legacy_compression_methods<1..2^8-1>;
          Extension extensions<8..2^16-1>;
      } ClientHello;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140853268-7988270f-c096-46e0-bad8-3e0285a50861.png)

### (3) Server Hello
包含：
* TLS协议版本
* 随机数，重要性和clinet随机数一样
* session id
* cipher suite，server选择的用于后续会话
* compression method
* extension

SPEC定义：  
```bash
      struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id_echo<0..32>;
          CipherSuite cipher_suite;
          uint8 legacy_compression_method = 0;
          Extension extensions<6..2^16-1>;
      } ServerHello;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140855623-d94d237d-1c3d-4304-992c-7027445d6bfb.png)


## 2 Server Parameters
   The next two messages from the server, EncryptedExtensions and
   CertificateRequest, contain information from the server that
   determines the rest of the handshake.  These messages are encrypted
   with keys derived from the server_handshake_traffic_secret.
### (1) Encrypted Extensions
EncryptedExtensions消息必须在ServerHello后马上发送，该消息由server_handshake_traffic_secret导出的密钥加密。

SPEC定义：  
```bash
      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140855675-1c4519a7-24d3-47c4-a99f-ff997e61e032.png)

### (2) Certificate Request（可选）
server侧请求client侧的证书，从而验证client的身份。

SPEC定义：  
```bash
      struct {
          opaque certificate_request_context<0..2^8-1>;
          Extension extensions<2..2^16-1>;
      } CertificateRequest;
```

##  3 Authentication Messages
   TLS generally uses a common set of
   messages for authentication, key confirmation, and handshake
   integrity: Certificate, CertificateVerify, and Finished. (The PSK
   binders also perform key confirmation, in a similar fashion.)  These
   three messages are always sent as the last messages in their
   handshake flight.  The **Certificate and CertificateVerify messages are
   only sent under certain circumstances**.  The
   **Finished message is always sent as part of the Authentication Block**.
   **These messages are encrypted under keys derived from the**
   **[sender]_handshake_traffic_secret**.

* Certificate Message：用来做server的认证
* CertificateVerify：对Transcript-Hash(Handshake Context, Certificate)的签名
* Finished：Transcript-Hash(Handshake Context, Certificate, CertificateVerify)的MAC值

Handshake context和MAC Base Key：
```bash
   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   | Server    | ClientHello ... later   | server_handshake_traffic_   |
   |           | of EncryptedExtensions/ | secret                      |
   |           | CertificateRequest      |                             |
   |           |                         |                             |
   | Client    | ClientHello ... later   | client_handshake_traffic_   |
   |           | of server               | secret                      |
   |           | Finished/EndOfEarlyData |                             |
   |           |                         |                             |
   | Post-     | ClientHello ... client  | client_application_traffic_ |
   | Handshake | Finished +              | secret_N                    |
   |           | CertificateRequest      |                             |
   +-----------+-------------------------+-----------------------------+
```

### (1) Certificate(可选)
无论何时经过协商一致以后的密钥交换算法需要使用证书进行认证的，Server 就必须发送一个 Certificate。  
Server Certificate 消息紧跟着 ServerHello 之后，通常他们俩者在同一个网络包中，即同一个 TLS 记录层消息中。

SPEC定义：  
```bash
      enum {
          X509(0),
          RawPublicKey(2),
          (255)
      } CertificateType;

      struct {
          select (certificate_type) {
              case RawPublicKey:
                /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

              case X509:
                opaque cert_data<1..2^24-1>;
          };
          Extension extensions<0..2^16-1>;
      } CertificateEntry;

      struct {
          opaque certificate_request_context<0..2^8-1>;
          CertificateEntry certificate_list<0..2^24-1>;
      } Certificate;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140861892-5aa469d5-76de-445a-b2ad-f2c75054b663.png)

### (2) Certificate Verify(可选)
用来验证endpoint的身份，使用证书对应的私钥进行签名。  
这条消息必须跟在Certificate消息之后，Finished消息之前。

SPEC定义： 
```bash
      struct {
          SignatureScheme algorithm;
          opaque signature<0..2^16-1>;
      } CertificateVerify;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140862503-3fe50bd4-ee4b-4079-a866-e9fa0d780eef.png)

### (3) Finished
对整个握手的MAC值，这个阶段提供了key confirmation，将endpoint的identity和交换的key绑定在一起，在PSK mode可以认证握手。

SPEC定义： 
```bash
   finished_key =
       HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)

   Structure of this message:

      struct {
          opaque verify_data[Hash.length];
      } Finished;

   The verify_data value is computed as follows:

      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))

      * Only included if present.
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140862881-15047757-fbe8-4e32-807b-cd1bda936054.png)


## 4 Post-Handshake Messages
### (1) New Session Ticket Message

SPEC定义：
```bash
      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
```
抓包：  
![image](https://user-images.githubusercontent.com/20694600/140865037-7cc53fc2-c00a-4fc8-a029-e3ee8be5ac0d.png)

### (2) Post-Handshake Authentication
SPEC定义：
```bash
      enum {
          update_not_requested(0), update_requested(1), (255)
      } KeyUpdateRequest;

      struct {
          KeyUpdateRequest request_update;
      } KeyUpdate;
```
