在1-RTT的握手完成后，server和client可以用shared key将session parameters打包成resumption secret用于后续的0-RTT。  
在后续的0-RTT中，server需要重新获取resumption secret，有两种方式，在首次完整握手后，server可以：
1. 将session chches储存在本地，发送给client一个lookup key用于标识当前server cache在local database中的位置。
当client发送0-RTT请求时，需要将lookup key放在0-RTT消息中。
2. 发送session ticket，server使用一把长期存在的session ticket encryption key（STEK）将resumption secret加密成session ticket。
当client发送0-RTT时，需要将session ticket包含在0-RTT消息中，server接收到后用本地的STEK解密。

TO-DO: server怎么判断client发送的resumption secret的确是当前client所有？AUTHENTICATION

在首次发送的0-RTT数据中，包含加密的应用数据，是由resumption secret和public client random value派生的key所加密。
TO-DO: resumption secret不是加密的吗，怎么使用？  

在0-RTT数据中也包含了DH参数，当server接收到0-RTT数据后，会协商出session key，用于保护后续的应用数据和握手信息。
所以受resumption secret加密的只有0-RTT的应用数据。



REFERENCE:
https://link.springer.com/article/10.1007/s00145-021-09385-0#Sec1
