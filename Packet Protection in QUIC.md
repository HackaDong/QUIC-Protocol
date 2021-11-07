# Packet Protection
Packet numbers are divided into three spaces in QUIC:
* All Initial packets 
* All Handshake packets
* All 0-RTT and 1-RTT packets

每个packet type都有不同的protection keys，所以不同packet number space之间的包都是cryptographic separation。

QUIC packets have varying protections depending on their type:
* **Version Negotiation** packets have no cryptographic protection
* **Retry** packets use AEAD_AES_128_GCM to provide protection against accidental modification and to limit the entities that can produce a valid Retry
* **Initial** packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the first Initial packet sent by the client
* All **other** packets have strong cryptographic protections for confidentiality and integrity, using keys and algorithms negotiated by TLS.

## Packet Protection Keys
QUIC的packet protection keys和TLS record protection keys是相似的。

在不同方向上（client-server），每个encryption level都有不同的密钥来保护packet，密钥的生成使用的是TLS的方法（HKDF），除了Initial encryption level，它使用client's Destination Connection ID来生成密钥。

HKDF使用current encryption level和不同的label当作KDF的输入来生成AEAD key：
1. packet protection key：“quic key”，密钥长度取决于AEAD算法
2. IV：“quic iv”， 长度为AEAD nonce，最短8 bytes
3. header protection key：“quic hp”，密钥长度取决于header protection algorithm

## HKDF简介
KDF是加密系统中十分基本和必要的组件。KDF的任务是，给定某初始密钥材料(IKM，initial keying material)，以及可选的salt，导出1或多个密码级强度的密钥。

HKDF则是KDF和HMAC的结合，具体参考RFC5869，主要包含两个步骤：
1. extract，将用户输入的密钥尽量伪随机化，一般使用hash函数完成
```bash
HKDF_Extract(salt, IKM) -> PRK # Pseudorandom Key
# 如果使用HMAC函数，则可以表示为：
HMAC_Hash(salt, IKM) -> PRK
```
2. expand，通过一系列的hash运算将密钥扩展到预期长度
```bash
HKDF_Expand(PRK, info, L) -> OKM
#伪代码
N = ceil(L/HashLen) // 向上取整，保证T的长度大于等于L
T = T(1) | T(2) | T(3) | ... | T(N)
OKM = first L octets of T // 裁剪成L个字节

where:
T(0) = empty string (zero length)
T(1) = HMAC_Hash(PRK, T(0) || info || 0x01)
T(2) = HMAC_Hash(PRK, T(1) || info || 0x02)
T(3) = HMAC_Hash(PRK, T(2) || info || 0x03)
...

// 0x01 0x02 0x03是递增的单字节常量
```
输入：
* PRK：HKDF_Extract的输出
* info：可选的上下文信息，默认是空字符串“”，当IKM被用于多种业务时，就可以用info来保证导出不一样的OKM
* L：指定输出的OKM的字节长度，不能超过255*HashLen
输出:
* OKM: 输出密钥材料

TLS1.3中HKDF Expand（Derive-Secret）函数定义如下：
```bash
       HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

       Where HkdfLabel is specified as:

       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;

       Derive-Secret(Secret, Label, Messages) =
            HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)
```
> 其中HKDF-Extract两个参数，通常使用当前密钥的状态作为salt值，PSK或DHE shared secret作为IKM


## Initial Secrets
Initial Packet密钥的派生方式不同于TLS，它使用client第一个Initial packet中的Destination Connection ID来派生密钥，长度为32 bytes。
```bash
initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
initial_secret = HKDF-Extract(initial_salt, 
                              client_dst_connection_id)
client_initial_secret = HKDF-Expand-Label(initial_secret,
                                         "client in", "",
                                          Hash.length)
server_initial_secret = HKDF-Expand-Label(initial_secret,
                                         "server in", "",
                                          Hash.length)
```
> salt值在以后的版本中会随机生成，用来防止中间人攻击
> HKDF-Expand-Label中使用的Destination Connection ID是client在Initial packet中随机生成的，如果client在收到Retry packet之后重新生成Initial packet，其中Destination Connection ID是由server来指定的
> Destination Connection ID最长20 bytes


## Handshake Secrets和0-RTT&1RTT Secrets
包括Handshake space和1-RTT（0-RTT） space，密钥派生和TLS保持一致，参考RFC8446，section 7。

在下面的key derivation图中：
* HKDF-Extract用上面的输入作为salt，左边的输入作为IKM
* Derive-Secret中箭头源为PSK
* "0"表示hash长度为0的string
### Early Secrets(0-RTT)
```bash
             0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
```
### Handshake Packet Secrets
```bash
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
```
### 1-RTT Packet Secrets
```bash
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
             +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret
```
### Traffic Key Calculation
Traffic Key是不同阶段用来加密数据的密钥，由上述不同的secret生成：
```bash
   [sender]_write_key = HKDF-Expand-Label(Secret, "quic key", "", key_length)
   [sender]_write_iv  = HKDF-Expand-Label(Secret, "quic iv", "", iv_length)

   [sender] denotes the sending side.  The value of Secret for each
   record type is shown in the table below.

       +-------------------+---------------------------------------+
       | Record Type       | Secret                                |
       +-------------------+---------------------------------------+
       | 0-RTT Application | client_early_traffic_secret           |
       |                   |                                       |
       | Handshake         | [sender]_handshake_traffic_secret     |
       |                   |                                       |
       | Application Data  | [sender]_application_traffic_secret_N |
       +-------------------+---------------------------------------+
```
> 在QUIC-TLS中，label由TLS的`key`和`iv`变成了QUIC的`quic key`和`quic iv`

比如server侧1-RTT需要计算：
* HKDF-Extract
  * Handshake Secret
  * Master Secret
* Derive-Secret
  * server_handshake_traffic_secret
  * server_application_traffic_secret_0
  * exporter_master_secret
  * resumption_master_secret
* Traffic Key
  * server_handshake_traffic_secret_write_key
  * server_handshake_traffic_secret_write_iv
  * server_application_traffic_secret_0_write_key
  * server_application_traffic_secret_0_write_iv
