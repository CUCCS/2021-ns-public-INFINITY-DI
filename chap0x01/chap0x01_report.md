#  基于 VirtualBox 的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

- VirtualBox 虚拟机
- 攻击者主机（Attacker）：attacker-kali
- 网关（Gateway, GW）：Gateway-debin
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali/Victim-XP-1/Victim-XP-2/victim-debian-2

## 实验要求

- 虚拟硬盘配置成多重加载，效果如下图所示；

![img](img\vb-multi-attach.png)

- 搭建满足如下拓扑图所示的虚拟机网络拓扑；

![img](img/vb-exp-layout.png)

> 根据实验宿主机的性能条件，可以适度精简靶机数量

- 完成以下网络连通性测试；
  - [ ] 靶机可以直接访问攻击者主机
  - [ ] 攻击者主机无法直接访问靶机
  - [ ] 网关可以直接访问攻击者主机和靶机
  - [ ] 靶机的所有对外上下行流量必须经过网关
  - [ ] 所有节点均可以访问互联网

## 实验过程

- 将虚拟硬盘`debian`和`xp`配置为多重加载

![debin](img\debian.png)



![xp](img\xp.png)

- 修改网关的网络配置

  ![gateway](img\gateway.png)

	- 查看ip地址

![gateway_ip](img\gateway_ip.png)

| 网络类型        | IP地址       |
| :-------------- | ------------ |
| NAT网络         | 10.0.2.15    |
| Host-Only       | 192.168.46.3 |
| 内部网络intnet1 | 172.16.111.1 |
| 内部网络intnet2 | 172.16.222.1 |

- Victim-Kali	

  ![victim-kali](img\victim-kali.png)

![victim-kali-ip](img\victim-kali-ip.png)

| 网络类型        | IP地址         |
| --------------- | -------------- |
| 内部网络intnet1 | 172.16.111.111 |

- victim-xp-1

  ![xp-1](img\xp-1.png)

![xp-1-ip](img\xp-1-ip.png)

| 网络类型        | IP地址         |
| --------------- | -------------- |
| 内部网络intnet1 | 172.16.111.106 |

- victim-debian2

  ![debian-2](img\debian-2.png)

  

![debian2-ip](img\debian2-ip.png)

| 网络类型        | IP地址         |
| --------------- | -------------- |
| 内部网络intnet2 | 172.16.222.114 |

- victim-xp-2

  ![xp-2](img\xp-2.png)

![xp-2-ip](img\xp-2-ip.png)

| 网络类型        | IP地址         |
| --------------- | -------------- |
| 内部网络intnet2 | 172.16.222.118 |

- attacker-kali

  ![attacker](img\attacker.png)

![attacker-ip](img\attacker-ip.png)

| 网络类型 | IP地址   |
| -------- | -------- |
| NAT网络  | 10.0.2.6 |

- **连通性测试**
  1. 靶机可以直接访问主机

![xp1-at](img\xp1-at.png)

![db-at](img\db-at.png)



2. 攻击者主机无法直接访问靶机

![at-intnet](img\at-intnet.png)

3. 网关可以直接访问攻击者主机和靶机

   ![gw-xp-at](img\gw-xp-at.png)

4. 靶机的所有对外上下行流量必须经过网关

   ![pcap](img\pcap.png)

   ![pcap1](img\pcap1.png)

5. 所有结点均可以访问互联网

   **intnet1**

   ![xp1 -5](img\xp1 -5.png)

   **intnet2**

   ![db-5](img\db-5.png)

   **NAT网络**



![at-5](img\at-5.png)

## 参考资料

[基于 VirtualBox 的网络攻防基础环境搭建](https://c4pr1c3.github.io/cuc-ns/chap0x01/exp.html)

