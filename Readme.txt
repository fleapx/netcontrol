本工程用于实现Linux下进程粒度的网络策略控制，适合大型机房部署

确保so源码中不存在hook函数调用
    objdump -T /lib64/libtaurus.so | grep -E "connect|accept|recv|send|bind"
启动server：
    service taurus start
测试deploy：
    service taurus cctrl "{\"cmd\":\"setpolicy\",\"folder\":\"/etc/taurus.config\"}"
测试switch：
    service taurus cctrl "{\"cmd":\"setswitch",\"switch\":\"on\"}"
    service taurus cctrl "{\"cmd\":\"setswitch\",\"switch\":\"off\"}"
停止server：
     service taurus stop
查找日志：
    service taurus qlog "{\"filter\":\"accept\",\"begint\":\"20180920_08:00:00\",\"endt\":\"20180920_08:10:00\"}"
    service taurus qlog "{\"filter\":\"deny\",\"begint\":\"20180920_08:00:00\",\"endt\":\"20180920_08:10:00\"}"
    service taurus qlog "{\"filter\":\"judge\",\"begint\":\"20180920_08:00:00\",\"endt\":\"20180920_08:10:00\"}"
预置策略：
    /etc/taurus.config/{policy.json,port.json,machine.json,white.json,health.json}
备份策略：
    /etc/taurus.config.backup/{policy.json,port.json,machine.json,white.json,health.json}
杀进程：
    ps aux | grep tau | grep -v grep | awk '{print $2}' | xargs kill -9
调试日志：
    tail -f /var/log/taurus.log               tail -f /var/log/messages(未设置日志)
单进程测试：
    LD_PRELOAD=/lib64/libtaurus.so /usr/sbin/sshd
    for n in $(seq 100); do LD_PRELOAD=/lib64/libtaurus.so ping www.baidu.com; done
资源占用：
    top -c -p `ps aux | grep tau | grep -v grep | awk '{print $2}' | xargs | tr " " ","`
    htop -s PID -p `ps aux | grep tau | grep -v grep | awk '{print $2}' | tr "\n" ","`
    valgrind -v  --trace-children=yes --log-file=$2%p $1  --tool=memcheck --leak-check=full --leak-resolution=high --show-leak-kinds=all --show-mismatched-frees=yes --undef-value-errors=no --track-fds=yes --num-callers=50  taurus_starter
客户端创建：
    python testcon.py --local_port=80
服务器创建：
    python testcon.py --remote_addr=61.135.169.125 --remote_port=80
部署libtaurus：
    # 保证文件存在
    mkdir /etc/taurus.config.backup && mkdir /etc/taurus.config
    touch /etc/ld.so.preload; cp -f /etc/ld.so.preload /etc/ld.so.preload.bak
    # 追加libtaurus.so到preload
    if [ `grep -c "taurus" /etc/ld.so.preload.bak` -eq '0' ]; then echo /lib64/libtaurus.so >> /etc/ld.so.preload.bak ; fi
    # 绑定文件，避免因bug导致无法重启
    mount --bind /etc/ld.so.preload.bak /etc/ld.so.preload
    

服务器测试：			
    1.服务器不存在，文件存在，客户端可检测出 	√
    2.服务器使用已有文件可正常工作 		√
    3.客户端并发写，服务器正常                                 √
    4.客户端在服务器响应前退出                                 √

策略测试：

    1.测试环回地址    
        127.0.0.0-127.255.255.255

    2.测试白名单    
        exe    
        md5    
        srcip   
        dstip     
        
    3.测试云控

    4.测试连入连接
        localport
        remoteaddr
        localport + remoteaddr

    5.测试连出连接
        remoteaddr                          √
        remoteport                          
        remoteaddr + remoteport

    6.policy测试
        base_rules 可用性
            direction: IN   OUT
            action: ACCEPT   REJECT
            local port
            remote addrtype: 1    2    3    6    255
            remote port
       ruls 可用性
            direction: IN   OUT
            action: ACCEPT   REJECT
            local port
            remote addrtype: 1    2    3    6    255
            remote port
    
    7. machine测试
        重解析
            addr type: 4    5
        addr解析
            addrtype: 1    2    3    6    255

    8. 范围测试
        addrtype: 1    2    3    6    255
        protocol:TCP|UDP|RAW
        direction:IN|OUT ALL
        process:["1.exe","2.exe"]
        md5:[]

    10. health测试
        待定

    11. 其他：
        无策略放行
        放行taurus_*

避免重启失败：/etc/init.d/taurus
if [  -f /tmp/test.log  ]; then
  rm -f /tmp/test.log
  echo exist >> /tmp/testlog
else
  touch /tmp/test.log
  echo nonexist >> /tmp/testlog
  /usr/bin/taurus_starter "$@"
fi
