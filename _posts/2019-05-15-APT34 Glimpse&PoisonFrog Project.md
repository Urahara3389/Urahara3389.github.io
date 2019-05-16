---
layout: post
title: APT34 Glimpse&PoisonFrog 项目分析
date: 2019-05-15 18:43:02
categories: [Red Team, APT, C2]
---

> 本文首发[绿盟科技技术博客](http://blog.nsfocus.net/apt34-glimpsepoisonfrog/)

## 0x01  简介

近期在[Lab Dookhtegan Telegram Chanel](https://t.me/lab_dookhtegan)中泄露的关于APT34的攻击工具项目、攻击成果记录及部分组织成员信息的事件，引发业界威胁情报及Red Team领域的安全人员强烈关注。类似于2017年Shadow Brokers泄漏的NSA攻击工具事件，但APT34工具的工程化程度和威胁影响力远不及NSA的泄露内容。就C2分析该组织习惯使用DNS隧道技术，并以文件系统来作为信息交互的媒体，这是一种非常规的实现方法，我们将在本文中对相关远控工具进行分析并尝试完成攻击功能还原。

## 0x02 TTPs分析

该组织被公开威胁情报平台关联命名为[APT34](https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html)、[Oilrig](https://unit42.paloaltonetworks.com/tag/oilrig/)或者[HelixKitten](https://attack.mitre.org/groups/G0049/) 。自2014年，FireEye就已追踪到APT34根据伊朗的战略利益进行了侦察。该组织主要在中东开展活动，重点针对金融，政府，能源，化工，电信和其他行业。对中东金融，能源和政府组织的反复攻击聚焦导致FireEye评估这些行业是APT34的主要关注点。依据与伊朗行动相关的基础设施、时机以及与伊朗国家利益保持一致也使FireEye评估APT34代表伊朗政府行事。

**本次泄漏工具列表如下：**

- Glimpse（基于PowerShell的的新版木马，Palo Alto Networks命名为BondUpdater）
- PoisonFrog（旧版BondUpdater）
- HyperShell
- HighShell（Palo Alto Networks称之为TwoFace）
- MinionProject（fox管理界面，加载了HighShell模块）
- Webmask（HTTP代理劫持工具，DNSpionage的主要工具，用于DNS修改）

本次泄漏工具与以往APT34开源情报进行TTPs对比分析，如下图所示，蓝色代表开源威胁情报当中APT34所涉及的技术，红色代表本次事件泄漏工具所涉及技术（注意出现的红色模块均覆盖到蓝色模块），可以发现泄漏工具技术均覆盖到APT34开源情报TTPs，并占据了1/5的内容，涉及到攻击链中执行和C2这两块相当重要的攻击阶段，所以这次泄漏事件对于APT34组织来说也是相当受打击的。

![](http://reverse-tcp.xyz/static/img/posts/APT34/APT34_TTPs.jpg)

通过TTPs分析我们认为此次泄漏工具集与[OilRig](https://attack.mitre.org/groups/G0049/)攻击者使用的一致（另外泄漏的webshell后门全球的受影响的地区分布和行业分布也和公开威胁情报显示内容一致），并且自2016年5月以来，OilRig使用了DNS隧道进行攻击的远程控制程序，并且已经使用不同的隧道协议为其工具集（来源：[Palo Alto Networks’ Unit 42 research team](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/)）。DNS Tunneling技术已经很成熟了，实现工具类似dns2tcp、iodine、dnscat2等也很多，包括Cobalt Strike以及MSF中也都有相应的模块。将数据封装在DNS协议中传输建立隐蔽通信隧道已经是高级威胁团伙的标配工具，DNS的无处不在（以及经常缺乏安全审计）可以实现非常优雅和微妙的方法来进行通信和共享数据滥用，超出了协议的初衷。DNS隧道存在延迟加密、跨平台、动静小的特点，但存在不稳定及速度慢等特点，因此相比于其他的隧道技术，它更适合在高度安全目标环境中穿透内网所用，红队在评估过程的有限时间内也可以选择性使用DNS隧道来维持攻击链不被蓝队斩断。

此次泄漏工具当中涉及到的远控工具就是一些开源情报中提到的BOUNDUPDATER，OilRig内部分为老版本PoisonFrog和新版本Glimpse，这可能是目前已知的最完整的APT34项目，除了依靠DNS协议外还依靠文件系统来完成命令控制和数据传输，这是一个非常不寻常的通信解决方案，本文将对两款工具进行简单分析并尝试完成攻击功能还原。

 

## 0x03  Glimpse项目

泄漏Glimpse项目文件列表如下

```
├── Glimpse
│   ├── Agent
│   │   ├── dns.ps1
│   │   ├── dns_main.ps1
│   │   ├── refineddns_main.ps1
│   │   └── runner_.vbs
│   ├── Read\ me.txt
│   ├── panel
│   │   ├── ToggleSwitch.dll
│   │   └── newPanel-dbg.exe
│   └── server
│   └── srvr.js
```

Readme.txt为项目部署说明文件
 *runner_.vbs*脚本用来启动当前目录下的PowerShell脚本文件，需要配合其他Execution方法去启动执行，*dns.ps1*、*dns_main.ps1*、*refineddns_main.ps1*三个脚本文件功能基本一致，另外两个文件在dns_main.ps1的基础上做了变量名混淆，sacr.js使用nodejs开发作为服务端提供DNS服务用于与agent的交互，交互过程大致如下：

Agent部分*$aa_domain_bb*变量为需要向C2充当权威域名服务器去查询的主域名(默认为[example.com](http://example.com))。函数*aa_ping_response_bb*和*aa_text_response_bb*将数据编码后已PING或者TEXT的方式完成DNS正向和反向解析请求，期间使用IP99.250.250.199来判断，用来传输不同的信息。
 ![](http://reverse-tcp.xyz/static/img/posts/APT34/image002.png)

客户端agent最初创建文件夹*%public%\Libraries*并判断lock是否存在，如果不存在，创建文件并写入当前powershell进程的pid；如果文件存在，读取文件创建时间，如果距离现在的时间超过10分钟，那么会退出进程并删除lock文件，然后生成识别agent目标系统的标识符，并写入文件*%public%\Libraries\quid*

通信管理功能由agent端*aa_AdrGen_bb*完成，它实现控制发送和接收信息。解码的action类型存储在变量*aa_act_bb*中，从服务端可以看出包括： 
 ![](http://reverse-tcp.xyz/static/img/posts/APT34/image003.png)

- Action M：如果代理已经注册到C2，则此命令的作用类似于ping，它会将基本信息更新到相应的agent文件夹。如果是agent第一次回连C2，服务端会去创建相应的文件夹去存放等待、接受不了、完成的命令和发送和已发送的信息；
- Action W：等待需要执行命令的TXT请求，在注册阶段之后执行的第一个命令是标记为10100的命令，其内容为：“whoami＆ipconfig / all”（泄漏文件中dns_main.ps1文件错误将Action W 写为P：`$aa_change_receive_mode_address_bb      = aa_AdrGen_bb “000” “P” “” “” “r” $rn`）
- Action D：等待需要执行命令的TXT请求。将标记的任务作为输入，并将其转发到请求agent的文件的Base64编码内容。
- Action 0 此请求使权威DNS（C2）向agent响应wait文件夹中的请求文件。如果没有文件在wait文件夹中，则C2响应返回ip（11.24.237.110）的A记录，如果有文件，C2响应字段“24.125”的A记录值(*"24.125."      + fileNameTmp.substring(0, 2) + "." + fileNameTmp.substring(2,      5)* )
- Action 1 此请求使权威DNS（C2）向agent响应文件内容。根据RFC4408，它实现了一个多应答链，用于发送大于255个字符的文件。 
- Action 2 此请求使权威DNS（C2）从agent接收文件。发送完所有数据后，agent将发出带有“COCTabCOCT”的最终DNS查询。此查询通知C2服务器agent已完成信息发送。

此过程当中agent会创建以下文件夹，运行情况如下图所示

```
%public%\Libraries\files
%public%\Libraries\<agentid>
%public%\Libraries\<agentid>\reveivebox
%public%\Libraries\<agentid>\sendbox
%public%\Libraries\<agentid>\done
```

![/C:/0ef058f6ab85ad7f7f2f6ef27e62abe5](http://reverse-tcp.xyz/static/img/posts/APT34/image004.png)

服务端程序在此过程当中会在/Glimpse/dns/agentid/目录下创建wait、receive、done、sended、sending等子文件夹，通过这些子目录下的文件读写来实现与agent的通信。Server端srvr.js运行情况如下图所示

![](http://reverse-tcp.xyz/static/img/posts/APT34/image005.png)

整个过程当中的流量内容

![](http://reverse-tcp.xyz/static/img/posts/APT34/image006.png)
 Panel部分为Glimpse项目图形化控制界面，包括显示agent上线列表、命令执行、文件上传下载、查看执行结果、切换DNS请求方式、 刷新等功能

![/C:/7f6f15c884697b42b1436a451cf41004](http://reverse-tcp.xyz/static/img/posts/APT34/Glimpse_v1.0.5.png)

为防止工具被二次恶意利用，这里不提供项目的具体搭建方法。

**该工具的公开线索**

- Palo Alto Networks将其命名为Updated      BondUpdater，对样本的分析资料：https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/

 

## 0x04  PoisonFrog项目

泄漏PoisonFrog项目包含两个版本，主要是agent部分poisonfrog.ps1文件内容不一致，项目文件列表如下

```
├── posionfrog
│   ├── agent
│   │   └── poisonfrog.ps1
│   └── serverside
│   ├── 0000000000.bat
│   ├── 9999999999.bat
│   ├── config.json
│   ├── installing
│   │   ├── filesList
│   │   ├── install_pachages.bat
│   │   ├── installing\ mongo_nodejs
│   │   └── stop\ dnsmasq
│   ├── routes
│   │   └── index.js
│   └── views
│   ├── agents.ejs
│   ├── login.ejs
│   ├── notfound.ejs
│   ├── panel.html
│   └── result.ejs
```

PoisonFrog项目与FireEye在2017年12月公开的面相中东的攻击事件情报当中提到的BONDUPDATER程序有直接关联。
 Poison Frog服务器端使用Nodejs开发，Poison Frog服务器端运行两个poisonfrog.ps1释放文件不一样，一个版本释放dUpdater.ps1和hUpdater.ps1，第二个版本多释放一个UpdateTask.vbs文件，该文件用来加载运行dUpdater.ps1和hUpdater.ps1两个PowerShell脚本，运行后同样依靠文件系统和上传下载完成与C2的交互，通过创建计划任务每10分钟执行一次agent。
 **该工具的公开线索**

- APT34曾利用CVE-2017-11882以文档攻击方式传播，分析资料：https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
- Palo Alto Networks将其命名为Early      BondUpdater，分析资料：https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/

## 0x05  总结

此次泄漏PoisonFrog和Glimpse项目是多模块的远程控制工具，通过TTPs的分析我们可以大致确认泄漏工具和公开威胁情报当中对OilRig工具集的分析一致，但我们也看到项目文件存在缺失和编码错误(或被篡改)等情况。另外Glimpse项目的成功运行需要配合DNS劫持来完成，操作相对复杂，我们猜测该工具不会被大量滥用。还有值得注意的是DNS信息交互使用文件来存储信息并同步操作，这是一种不同寻常的实现方式，猜测可以实现许多panel同时控制C2，这个CobaltStrick的teamserver有异曲同工之妙，但技术实现上就差的比较多了。不管怎样此次泄漏或多或少都对红队对手技术模拟、威胁情报等方面提供了极大的价值。

## 0x06  参考

[http://blog.nsfocus.net/apt34-event-analysis-report/](http://blog.nsfocus.net/apt34-event-analysis-report/)

 

 