# SCU_JiangAn_Dialer
川大江安宽带拨号器破解。

代码已经是近3年前写的了，从各个方面来说都不怎么样，但是因为是自用的程序，所以就一直没有怎么改动过。

更详细的说明请访问：[川大江安校区宽带破解](http://xiadong.info/2016/06/%E5%B7%9D%E5%A4%A7%E6%B1%9F%E5%AE%89%E6%A0%A1%E5%8C%BA%E5%AE%BD%E5%B8%A6%E7%A0%B4%E8%A7%A3/)

目前这个版本的代码是运行在我的OpenWRT路由器上的，拨号命令为：

    /usr/sbin/pppd nodetach ipparam %s ifname %s nodefaultroute usepeerdns persist maxfail 1 user %s password %s ip-up-script /lib/netifd/ppp-up ipv6-up-script /lib/netifd/ppp-up ip-down-script /lib/netifd/ppp-down ipv6-down-script /lib/netifd/ppp-down mtu 1492 mru 1492 plugin rp-pppoe.so nic-%s &

其中有5个用户指定参数（%s）；这条指令即使在不同的OpenWRT系统上也有可能略有区别，具体含义请参考相应的pppd手册。

在其他平台上使用时请修改为对应的拨号方法。

本程序使用libpcap（<http://www.tcpdump.org/>），编译时请自行安装。