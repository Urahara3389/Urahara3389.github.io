---
layout:     post
title:      "域渗透-信息收集基础"
subtitle:   "内网渗透-域环境"
date:       2016-12-16
author:     "Urahara"
header-img: "img/1e9a2b0d5bae82200a649cef7ddfc64c.jpg"
header-mask: 0.3
tags:
    - 渗透测试
    - 内网渗透
    - 域渗透

---

### 判断当前服务器是否在域内

1. **RDS** 如果目标服务器远程桌面服务开启，可尝试进行连接，若在用户名和密码栏下还有一个**登录到(L)**选项，下拉选项栏如果除了**计算机名（此计算机）**选项外还有其他选项，则此服务器可能位于域中，且选项名即为域名；

2. **net time /domain** 执行该命令，有三种情况：第一种如果存在域会从域控返回时间，并在第一行返回**域控及域名**；第二种如果当前当前服务器在域内但当前用户非域用户，则会返回**System error 5**就表示权限不够；最后一种就是返回“找不到域WORKGROUP的域控制器”表示当前网络环境为工作组而不存在域；

3. **ipconfig /all** 查看当前网络的DNS，一般在内网DNS服务器即为域控，很少将DNS与域控分开，除非内网很大存在多域环境；

4. **systeminfo** 系统信息当中含有两项：Domain和Logon Server，Domain即为域名，Logon Server为域控，但如果Domain显示为WORKGROUP则当前服务器不在域内；

5. **net config workstation** 其中工作域显示域名，同样若为WORKGROUP则非域环境，登录域表明当前用户是域用户登录还是本地用户登录；


### 域内信息收集

```
net group /domain  获得所有域用户组列表
net group “domain admins” /domain  获得域管理员列表
net group “enterprise admins” /domain  获得企业管理员列表
net localgroup administrators /domain 获取域内置administrators组用户
net group “domain controllers” /domain 获得域控制器列表
net group “domain computers” /domain 获得所有域成员计算机列表
net user /domain 获得所有域用户列表
net user someuser /domain 获得指定账户someuser的详细信息
net accounts /domain 获得域密码策略设置，密码长短，错误锁定等信息
nltest /domain_trusts 获取域信任信息
```

​	需要注意的是本地用户是无法运行以上所说说的所有命令的，因为本质上所有查询都是通过ldap协议去域控制器上查询，这个查询需要经过权限认证，只有域用户才有这个权限。当域用户运行查询命令时，会自动使用kerberos协议认证，无需额外输入账号密码。SYSTEM用户的情况比较特殊，在域中，除了普通用户外，所有机器都有一个机器用户，用户名是机器名后加$，本质上机器上的SYSTEM用户对应的就是域里面的机器用户，所以SYSTEM权限是可以运行之前说的查询命令的。

>  比如我们在获取到某域内服务器的administrator权限后，执行以上命令时出现权限不够情况，这时可通过PsExec将权限提升提升至System后再执行，具体命令为PsExec -s cmd

### 密码抓取

​	在内网渗透过程中，说白了就是不断进行信息收集，扩大攻击面，除了以上收集的信息外，我们最关注的也是当前服务器上的所有系统账号密码，这一般有三种情况，首先是服务器本地账户，其次是域用户，当然如果有狗屎运的话抓到域管的账号密码也不是没有可能的。

​	这里简单说一下抓取密码的姿势，第一种就是上传工具在服务器上抓hash，常用的工具有pwdump7、gethashes、QuarksPwDump、mimikaze等，这种方法有可能会被服务器上的防护软件干掉，碰到这种要不关杀软，要不删防护策略，再就是做免杀；还有一种就是导出注册表拖回本地进行导出，导出注册表的命令为`reg save hklm\sam sam.hive & reg save hklm\system system.hive & reg save hklm\security security.hive`，将生成文件拖回本地使用creddump7从注册表提取[mscash](https://github.com/Neohapsis/creddump7)，命令为`pwdump.py system.hive sam.hive`，这种方法的好处就是不用在意杀软。

​	首先考虑最差的结果，当前服务器上全为本地用户未获取到任何域用户信息，那么就可以使用这些账号密码组合去使用IPC共享或smb爆破去扫描其他主机，若爆破有结果那就可以登录至这些服务器继续抓取hash，直到遇见域用户为止；再者，如果当前已获得域用户账号密码，除非此时有ms14-068 kerberos漏洞或者GPP组策略漏洞可利用提升至域管权限，要不只能再继续进行用户登录迭代直至抓取到域管hash为止。

#### Referer

[https://www.t00ls.net/thread-30541-1-1.html](https://www.t00ls.net/thread-30541-1-1.html)

http://www.fuzzysecurity.com/tutorials/25.html

