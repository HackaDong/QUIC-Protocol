# 会话恢复

## TLS1.2
Session信息包含：
* 会话标识符(session identifier): 每个会话的唯一标识符
* 对端的证书(peer certificate): 对端的证书，一般为空
* 压缩算法(compression method): 一般不启用
* 密码套件(cipher spec): Client 和 Server 协商共同协商出来的密码套件
* 主密钥(master secret): 每个会话都会保存一份主密钥，注意不是预备主密钥
* 会话可恢复标识(is resumable): 标识会话是否可恢复

```bash
      Client                                                Server

      ClientHello                   -------->
                                                       ServerHello
                                                [ChangeCipherSpec]
                                    <--------             Finished
      [ChangeCipherSpec]
      Finished                      -------->
      Application Data              <------->     Application Data

          Figure 2.  Message flow for an abbreviated handshake
```

### 基于 Session ID 的会话恢复
* Server 通过 ClientHello 中协商出来的密钥套件必须和会话中的密钥套件是一致的，否则会话恢复失败，进行完整的握手。
* ClientHello 中的随机数和恢复之前会话所用的随机数是不同的，所以即使会话恢复了，由于 ClientHello 中随机数的不同，再次通过 PRF 生成的密钥块**(会话密钥)也是不同的**。增加了安全性。
* ClientHello 中的 Session ID 是明文传输，所以不应该在 Session ID 中包含敏感信息。并且握手最后一步的 **Finished 校验非常有必要，防止 Session ID 被篡改**。

基于 Session ID 的会话恢复的优点是:

* 减少网络延迟，握手耗时从 2-RTT -> 1-RTT
* 减少了 Client 和 Server 端的负载，减少了加密运算的 CPU 资源消耗

基于 Session ID 的会话恢复的缺点是:

* Server 存储会话信息，限制了 Server 的扩展能力。
* 分布式系统中，如果只是简单的在 Server 的内存中存储 Session Cache，那么多台机器的数据同步也是一个问题。

![image](https://user-images.githubusercontent.com/20694600/141683171-72613c4a-d968-40d6-b29d-92286c647ef4.png)

### 基于 Session Ticket 的会话恢复
思想是服务器取出它的所有会话数据（状态）并进行加密 (密钥只有服务器知道)，再以票证的方式发回客户端。
在接下来的连接中，客户端恢复会话时在 ClientHello 的扩展字段 session_ticket 中携带加密信息将票证提交回服务器，由服务器检查票证的完整性，解密其内容，再使用其中的信息恢复会话。

对于 Server 来说，解密 ticket 就可以得到主密钥，(注意这里和 SessionID 不同，有 Session ID 可以直接得到主密钥的信息)。
对于 Client 来说，完整握手的时候收到 Server 下发的 NewSessionTicket 子消息的时候，Client 会将 Ticket 和对应的预备主密钥存在 Client，简短握手的时候，一旦 Server 验证通过，可以进行简单握手的时候，Client 通过本地存储的预备主密钥生成主密钥，最终再生成会话密钥(密钥块)。

```bash
      Client                                                Server

      ClientHello
      (SessionTicket extension)     -------->
                                                       ServerHello
                                    (empty SessionTicket extension): 表示server支持session ticket
                                                  NewSessionTicket: (加密，重新生成，用于下次会话恢复)
                                                [ChangeCipherSpec]
                                    <--------             Finished
      [ChangeCipherSpec]
      Finished                      -------->
      Application Data              <------->     Application Data
```

NewSessionTicket消息格式：
```bash
      struct {
          uint32 ticket_lifetime_hint;
          opaque ticket<0..2^16-1>;
      } NewSessionTicket;

      struct {
          opaque key_name[16];
          opaque iv[16];
          opaque encrypted_state<0..2^16-1>;
          opaque mac[32];
      } ticket;
```
会话信息消息格式：
```bash
      struct {
          ProtocolVersion protocol_version;
          CipherSuite cipher_suite;
          CompressionMethod compression_method;
          opaque master_secret[48];
          ClientIdentity client_identity;
          uint32 timestamp;
      } StatePlaintext;
```

![image](https://user-images.githubusercontent.com/20694600/141683585-baeb8981-eae1-400c-bd67-d07c76ddcc04.png)

Client Hello:  
![image](https://user-images.githubusercontent.com/20694600/141683832-b5d80c77-0968-470d-9e3f-fc0fa824d2e3.png)

Server Hello:  
![image](https://user-images.githubusercontent.com/20694600/141683864-1f94bdc6-3102-4ba8-8dca-30f529c0b6c8.png)

New Session Tikcet:  
![image](https://user-images.githubusercontent.com/20694600/141684088-1b506bef-0e27-46ab-85ac-37232ed9ec80.png)




