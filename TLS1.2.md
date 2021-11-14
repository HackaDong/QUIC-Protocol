# TLS1.2

## Handshake Protocol
```bash
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data

             Figure 1.  Message flow for a full handshake

   * Indicates optional or situation-dependent messages that are not
   always sent.

   Note: To help avoid pipeline stalls, ChangeCipherSpec is an
   independent TLS protocol content type, and is not actually a TLS
   handshake message.
```

## Hello messages
ClientHello 和 ServerHello 建立了如下的属性: 
* 协议版本
* 会话 ID
* 密码套件,例如 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384：  
  密钥协商算法是 ECDHE，身份验证算法是 ECDSA，加密模式是 AES_256_GCM，由于 GCM 是属于 AEAD 加密模式，所以整个密码套件无须另外的 HMAC，SHA384 指的是 PRF 算法。

* 压缩算法
* 产生并交换两个随机数: ClientHello.random 和 ServerHello.random

```bash
      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;

      struct {
          ProtocolVersion server_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suite;
          CompressionMethod compression_method;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ServerHello;

      struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
      } Extension;

      enum {
          signature_algorithms(13), (65535)
      } ExtensionType;
```

## Server Certificate
Server Certificate 消息紧跟着 ServerHello 之后，通常他们俩者在同一个网络包中，即同一个 TLS 记录层消息中。

```bash
      opaque ASN.1Cert<1..2^24-1>;

      struct {
          ASN.1Cert certificate_list<0..2^24-1>;
      } Certificate;
```

## Server Key Exchange Message
ServerKeyExchange 消息由 Server 发送，但仅在 Server 证书消息(如果发送了)没有包含足够的数据以允许 Client 交换一个预密钥时。

对于 RSA 加密套件，Client 不需要额外参数就可以计算出预备主密钥，然后使用 Server 的公钥加密发送给 Server 端，所以不需要 Server Key Exchange 可以完成协商。

对于 ECDH 加密套件，DH公钥一般包含在Server证书中，如果没有，则通过此消息传递。
对于 ECDHE 加密套件，Server通过此消息传递DH公钥。

ServerKeyExchange 这个消息的目的就是传递了必要的密码信息，使得 Client 可以完成预备主密钥的通信：获得一个 Client 可用于完成一个密钥交换的 Diffie-Hellman 公钥(结果就是生成预备主密钥)或一个其它算法的公钥。

```bash
      enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
            /* may be extended, e.g., for ECDH -- see [TLSECC] */
           } KeyExchangeAlgorithm;

      struct {
          opaque dh_p<1..2^16-1>;
          opaque dh_g<1..2^16-1>;
          opaque dh_Ys<1..2^16-1>;
      } ServerDHParams;     /* Ephemeral DH parameters */

      dh_p
         The prime modulus used for the Diffie-Hellman operation.

      dh_g
         The generator used for the Diffie-Hellman operation.

      dh_Ys
         The server's Diffie-Hellman public value (g^X mod p).

      struct {
          select (KeyExchangeAlgorithm) {
              case dh_anon:
                  ServerDHParams params;
              case dhe_dss:
              case dhe_rsa:
                  ServerDHParams params;
                  digitally-signed struct {
                      opaque client_random[32];
                      opaque server_random[32];
                      ServerDHParams params;
                  } signed_params;
              case rsa:
              case dh_dss:
              case dh_rsa:
                  struct {} ;
                 /* message is omitted for rsa, dh_dss, and dh_rsa */
              /* may be extended, e.g., for ECDH -- see [TLSECC] */
          };
      } ServerKeyExchange;

      params
         The server's key exchange parameters.

      signed_params
         For non-anonymous key exchanges, a signature over the server's
         key exchange parameters.
```

Server 需要传递额外参数的密码套件主要 6 种，DHE_DSS、DHE_RSA、ECDHE_ECDSA、ECDHE_RSA、DH_anon、ECDH_anon，其他的密码套件不可用于 ServerKeyExchange 这个消息中。
一般 HTTPS 都会部署这 4 种密码套件：**ECDHE_RSA、DHE_RSA、ECDHE_ECDSA、RSA**。

## Certificate Request
如果 Server 发送了一个 CertificateRequest 消息，Client 必须发送 Certificate 消息。

## Server Hello Done
这个消息意味着 Server 发送完了所有支持密钥交换的消息，Client 能继续它的密钥协商，证书校验等步骤。

## Client Certificate
Client Certificate 消息的目的是传递 Client 的证书链给 Server；当验证 CertificateVerify 消息时(当 Client 的验证基于签名时)Server 会用它来验证或计算预备主密钥(对于静态的 Diffie-Hellman)。

## Client Key Exchange Message
在这个消息中设置了预备主密钥，或者通过 RSA 加密后直接传输，或者通过传输 Diffie-Hellman 参数来允许双方协商出一致的预备主密钥。

## Certificate Verify
如果 Client 发送了一个带签名能力的证书, 则需要发送以一个数字签名的 CertificateVerify 消息，以显式验证证书中私钥的所有权。

## Finished (加密)
一个 Finished 消息一直会在一个 change cipher spec 消息后立即发送，以证明密钥交换和认证过程是成功的。
一个 change cipher spec 消息必须在其它握手消息和结束消息之间被接收。

Finished 消息是第一个被刚刚协商的算法，密钥和机密保护的消息。
Finished 消息的接收者必须验证内容是正确的。
一旦一方已经发送了 Finished 消息且接收并验证了对端发送的 Finished 消息，就可以在连接上开始发送和接收应用数据。

```bash
      struct {
          opaque verify_data[verify_data_length];
      } Finished;

      verify_data
         PRF(master_secret, finished_label, Hash(handshake_messages))
            [0..verify_data_length-1];

      finished_label
         For Finished messages sent by the client, the string
         "client finished".  For Finished messages sent by the server,
         the string "server finished".
 ```
* handshake_messages:  
  所有在本次握手过程（不包括任何 HelloRequest 消息）到但不包括本消息的消息中的数据。这是只能在握手层中看见的数据且不包含记录层头。  
  client 发送的 Finished 消息的 handshake_messages 与 Server 发送的 Finished 消息不同，因为第二个被发送的要包含前一个。  
  Server 的 Finished 消息会包含 Client 的 Finished 子消息。  
  NOTE: 注意：ChangeCipherSpec 消息，alert 警报，和任何其它记录类型不是握手消息，不会被包含在 hash 计算中。同样，HelloRequest 消息也被握手 hash 忽略。

**Finished 子消息是 TLS 记录层加密保护的第一条消息。**

**Finished 子消息的存在的意义是什么呢？**

在所有的握手协议中，所有的子消息都没有加密和完整性保护，消息很容易篡改，改掉以后如果不检验，就会出现不安全的攻击。
为了避免握手期间存在消息被篡改的情况，所以 Client 和 Server 都需要校验一下对方的 Finished 子消息。

如果中间人在握手期间把 ClientHello 的 TLS 最高支持版本修改为 TLS 1.0，企图回退攻击，利用 TLS 旧版本中的漏洞。Server 收到中间人的 ClientHello 并不知道是否存在篡改，于是也按照 TLS 1.0 去协商。握手进行到最后一步，校验 Finished 子消息的时候，校验不通过，因为 Client 原本发的 ClientHello 中 TLS 最高支持版本是 TLS 1.2，那么产生的 Finished 子消息的 verify_data 与 Server 拿到篡改后的 ClientHello 计算出来的 verify_data 肯定不同。至此也就发现了中间存在篡改，握手失败。

## ChangeCipherSpec
为了防止 pipeline stalls，ChangeCipherSpec 是一种独立的 TLS 协议内容类型，并且事实上它不是一种 TLS 消息。

Client 发送一个 ChangeCipherSpec 消息，并且复制 pending 的 Cipher Spec 到当前的 Cipher Spec 中,
然后 Client 在新算法, 密钥确定后立即发送 Finished 消息。
作为回应，Server 会发送它自己的 ChangeCipherSpec 消息, 将 pending 的 Cipher Spec 转换为当前的 Cipher Spec，在新的 Cipher Spec 下发送 Finished 消息。
这时，握手完成，Client 和 Server 可以开始交换应用层数据。
应用数据一定不能在第一个握手完成前(在一个非TLS_NULL_WITH_NULL_NULL 类型的密码套件建立之前)发送。

## Wireshark抓包
基于RSA密钥协商算法的握手：
![image](https://user-images.githubusercontent.com/20694600/141672993-fe45320d-813f-4ee3-8d96-82bd2b746bdd.png)

Client Hello:  
![image](https://user-images.githubusercontent.com/20694600/141673636-40361431-bd0c-416b-bddd-ce35f1305400.png)

Server Hello && Server Certificate && Server Done:  
![image](https://user-images.githubusercontent.com/20694600/141673656-cb77c99f-9e60-488c-bd92-fd8c390a1778.png)

Client Key Exchange && Change Cipher Spec && Client Finished:  
![image](https://user-images.githubusercontent.com/20694600/141673677-96695eb6-945b-4cc4-84d6-036df1e4d623.png)

New Session Ticket && Change Cipher Spec && Server Finished:  
![image](https://user-images.githubusercontent.com/20694600/141673684-bd7e76da-14b5-4822-8617-c735ba90d060.png)

基于DH密钥协商算法的握手：
![image](https://user-images.githubusercontent.com/20694600/141673019-19dd2dd6-f4d9-483e-89ef-018dfc0b5e5e.png)

Client Hello:  
![image](https://user-images.githubusercontent.com/20694600/141673327-b118b99f-f10e-4f41-acd9-b30737d8795a.png)

Server Hello:  
![image](https://user-images.githubusercontent.com/20694600/141673351-b7730e69-7ac3-4895-aede-0d760d534cc1.png)

Server Certificate && Server Key Exchange && Server Done:  
![image](https://user-images.githubusercontent.com/20694600/141673374-0c968a51-b0ac-43d7-af2e-3e26f4bbf5d7.png)

Client Key Exchange && Change Cipher Spec && Client Finished:  
![image](https://user-images.githubusercontent.com/20694600/141673433-ed5cbeda-6a6b-42fe-9686-2d518dce0efd.png)

New Session Ticket && Change Cipher Spec && Server Finished:  
![image](https://user-images.githubusercontent.com/20694600/141673452-a4e6257d-432f-4ee1-b7cb-6688c0971912.png)

