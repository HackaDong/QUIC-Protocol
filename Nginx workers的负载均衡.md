Nginx通过accept_mutex来解决“惊群”问题和实现workers的负载均衡

解决“惊群”问题
nginx全局只有一把accept_mutex锁，每个worker都会尝试去获取ngx_trylock_accept_mutex
只有获取到锁的worker才能监听listening fd，也就是说同一时间只有一个worker能够处理http request

负载均衡
通过全局变量ngx_accept_disabled
ngx_accept_disabled = ngx_cycle->connection_n/8 - ngx_cycle->free_connection_n;
nginx初始化时ngx_accept_disabled为负数，其值为连接总数的7/8。
当它为负数时， 不会进行触发负载均衡操作，而当ngx_accept_disabled是正数时， 就会触发Nginx进行负载均衡操作了。 
Nginx的做法也很简单， 就是当ngx_accept_disabled是正数时当前进程将不再处理新连接事件（不会尝试去获取accept_mutex锁），
取而代之的仅仅是ngx_accept_disabled值减1。

TO-DO: EPOLL怎么解决负载均衡
