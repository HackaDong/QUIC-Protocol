1. cipher algorithms只保留了带AEAD的算法（hash用于KDF和MAC），从概念上与认证和密钥交换隔离开来
2. 0-RTT模式的引入，安全性有所牺牲
3. 基于公钥的密钥交换提供前向安全性，删除了静态RSA和DH算法
4. ServerHello后所有的握手信息均被加密，新引入【EncryptedExtensions】消息
5. KDF函数被重新设计，使用基于HMAC的HKDF算法（HMAC-based Extract-and-Expand Key Derivation Function）
6. 握手状态机重新设计，更加高效，删除了多余的消息，如加密套件交换【ChangeCipherSpec】
7. 椭圆曲线算法大行其道，新的签名算法被引入，如EdDSA
8. 密码套件安全性的优化，如RSA使用RSASSA-PSS padding模式，删除了压缩，DSA，自定义DHE群等
9. TLS1.2的版本协商机制被淘汰，改用extension中的version list
10. 会话重用中PSK-based加密套件被淘汰，改用PSK交换机制
11. 新的RFC: (e.g., RFC 5280 rather than RFC 3280)



1.2.  Major Differences from TLS 1.2

   The following is a list of the major functional differences between
   TLS 1.2 and TLS 1.3.  It is not intended to be exhaustive, and there
   are many minor differences.

   -  The list of supported symmetric encryption algorithms has been
      pruned of all algorithms that are considered legacy.  Those that
      remain are all Authenticated Encryption with Associated Data
      (AEAD) algorithms.  The cipher suite concept has been changed to
      separate the authentication and key exchange mechanisms from the
      record protection algorithm (including secret key length) and a
      hash to be used with both the key derivation function and
      handshake message authentication code (MAC).

   -  A zero round-trip time (0-RTT) mode was added, saving a round trip
      at connection setup for some application data, at the cost of
      certain security properties.

   -  Static RSA and Diffie-Hellman cipher suites have been removed; all
      public-key based key exchange mechanisms now provide forward
      secrecy.

   -  All handshake messages after the ServerHello are now encrypted.
      The newly introduced EncryptedExtensions message allows various
      extensions previously sent in the clear in the ServerHello to also
      enjoy confidentiality protection.

   -  The key derivation functions have been redesigned.  The new design
      allows easier analysis by cryptographers due to their improved key
      separation properties.  The HMAC-based Extract-and-Expand Key
      Derivation Function (HKDF) is used as an underlying primitive.

   -  The handshake state machine has been significantly restructured to
      be more consistent and to remove superfluous messages such as
      ChangeCipherSpec (except when needed for middlebox compatibility).

   -  Elliptic curve algorithms are now in the base spec, and new
      signature algorithms, such as EdDSA, are included.  TLS 1.3
      removed point format negotiation in favor of a single point format
      for each curve.
      
   -  Other cryptographic improvements were made, including changing the
      RSA padding to use the RSA Probabilistic Signature Scheme
      (RSASSA-PSS), and the removal of compression, the Digital
      Signature Algorithm (DSA), and custom Ephemeral Diffie-Hellman
      (DHE) groups.

   -  The TLS 1.2 version negotiation mechanism has been deprecated in
      favor of a version list in an extension.  This increases
      compatibility with existing servers that incorrectly implemented
      version negotiation.

   -  Session resumption with and without server-side state as well as
      the PSK-based cipher suites of earlier TLS versions have been
      replaced by a single new PSK exchange.

   -  References have been updated to point to the updated versions of
      RFCs, as appropriate (e.g., RFC 5280 rather than RFC 3280).
