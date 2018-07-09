---
layout:     post
title:      "Equation Group泄漏工具简单试用与MS17-010漏洞利用"
subtitle:   "Analysis of the Vulnerabilities"
date:       2017-04-17
author:     "Urahara"
categories: [Pentest, Red Team, FuzzBunch]

---



###  简介

Shadow Brokers周末公布的文件无疑对互联网造成了一次大地震，因为已经很久没有出现过像ms08-067这种级别的漏洞了，因此就被大家笑语说出了“指哪打哪”这样一个事实。而让人佩服的不仅是漏洞，还有泄漏出来的FuzzBunch攻击框架，但是这两天大家都是配合MSF来完成的漏洞利用，所以研究了一下自带的DanderSpritz工具，感觉也是挺震撼的。总之，个人觉得FuzzBunch是目前唯一可以和MSF媲美的攻击框架了。

> - 泄漏工具下载地址1: 原文件下载地址：[https://yadi.sk/d/NJqzpqo_3GxZA4](https://yadi.sk/d/NJqzpqo_3GxZA4)（Key：Reeeeeeeeeeeeeee）
> - 泄漏工具下载地址2： [https://github.com/x0rz/EQGRP_Lost_in_Translation](https://github.com/x0rz/EQGRP_Lost_in_Translation)

泄漏文件说明

| 泄漏文件               | 说明                              |
| ------------------ | ------------------------------- |
| odd.tar.xz.gpg     | 后门文件及相关文档                       |
| sha256sum.txt      | 文件的sha256哈希                     |
| swift.tar.xz.gpg   | SWIFT/EastNets信息                |
| windows.tar.xz.gpg | Fuzzbunch攻击框架- DanderSpritz攻击工具 |

### 测试环境

**攻击机：** 192.168.50.3  Win7 x32 

**靶机：** 192.168.50.120  Win7 SP1 x64 

**FuzzBunch运行环境要求：** windows、python2.6、pywin32、java

使用FuzzBunch之前，需要注释掉fb.py文件第26、27、28、72行代码

```
26  #LP_DIR      = os.path.join(FB_DIR, "listeningposts")
27  #EDE_DIR     = os.path.join(FB_DIR, "ede-exploits")
28  #TRIGGER_DIR = os.path.join(FB_DIR, "triggers")

72  #addplugins(fb, "ListeningPost", LP_DIR,      EDFPlugin)
```

### 测试步骤

在靶机上运行fb.py启动FuzzBunch攻击框架

新建项目并进行会话设置，包括目标IP、回调IP、Log目录及关闭重定向

![new project](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/new project.png)

完成以上步骤后我们就可以进入至fb shell当中，这里我们可以使用help命令查看使用帮助，并使用use命令来调用相关模块插件

![help](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/help.png)

![use](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/use.png)

插件被分解成几类：

- 目标识别和利用漏洞发现：Architouch、Rpctouch、Domaintouch、Smbtouch等；
- 漏洞利用：EternalBlue、Emeraldthread、Eclipsedwing、EternalRomance等；
- 攻击利用：Doublepulsar、Regread、Regwrite等；
- 后门模块：Mofconfig（可能为设置MOF后门的插件，但暂时未测试成功）。

然后我们通过使用Smbtouch插件执行execute命令使用smb协议来检测对方操作系统版本、架构、可利用的漏洞。

![smbtouch](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/smbtouch.png)

该例中发现Eternalblue可用，所以我们使用该插件插件进行MS17-010漏洞利用举例

![use Eternalblue](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/use Eternalblue.png)

接下来的设置大多使用默认值就行，需要注意的是在选择靶机操作系统时根据需要切换就行，这里我们选择1） WIN72K8R2，攻击模式选择 1） FB

![target and mode](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/target and mode.png)

Eternalblue模块设置成功

![Module-Eternalblue](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/Module-Eternalblue.png)

这里我们开始配合DanderSpritz工具进行利用，这东西有点像远控木马客户端，功能也非常强大。

在windows目录下有一个Start.jar文件，可以双击直接运行也可以运行start_lp.py文件来运行，启动时需要配置log目录为项目log路径（我们在启动FuzzBunch攻击框架时设置的目录加上项目名称即为项目日志目录）

![DanderSpritz start](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/DanderSpritz start.png)

启动后有三个error报错，可以不用理会（老外在Github上的更新版本不会存在此报错）

![DanderSpritz-error](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/DanderSpritz-error.png)

DanderSpritz中可以调用pc_prep工具来生成自己的payload，我们在console中输入pc_prep -sharedlib开始(Github更新版使用pc2.2_prep)

 ![pc_prep -sharedlib](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/pc_prep -sharedlib.png)

这里根据需求选择payload类型，由于目标操作系统是64位的，所以选择payload类型为3，其他配置如下

![pc_prep 2](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/pc_prep 2.png)

![pc_prep 2](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/pc_prep 3.png)

其中回调IP写攻击机IP地址，key使用default即可，完成以上步骤后就会成功在log目录中生成一个dll payload

![pc_prep 2](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/pc_prep 4.png)

接下来类似于msf，我们需要在PeddleCheap中设置监听，需要注意使用default key，监听端口也使用默认即可

![PeddleCheap](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/PeddleCheap.png)

![monitor](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/monitor.png)

端口监听成功

完成上述步骤后我们再次回到fb shell当中，使用Doublepulsar模块来上传我们上一步生成的payload完成漏洞利用，需要注意在配置时选择Rundll来进行dll注入，同时设置dllpayload为我们生成的payload文件，其他配置根据需求配置即可

DoublePulsar的4个功能：

- Ping： 检测后门是否部署成功
- RUNDLL：注入dll。
- RunShellcode：注入shellcode
- Uninstall:用于卸载系统上的后门 

![dll injection](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/dll injection.png)

dll注入成功

![dll injection success](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/dll injection success.png)

返回DanderSpritz查看监听情况，成功接受到来自靶机的连接请求，输入YES完成连接

![connection](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/connection.png)

接着DanderSpritz会自动完成大量的靶机信息收集，包括硬件信息、操作系统信息、网络信息等等，也会尝试破解密码、收集靶机上的安全防护软件信息等，并会将这些收集到的信息保存至log文件中

![Basic information](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/Basic information.png)

连接完成后，就可以使用DanderSpritz的各种插件了，例如文件管理、截屏、终端、编辑windows的事件日志、窃取靶机浏览器中的信息、usb监听等等

新建插件：

![plugin](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/plugin.png)

文件管理：

![filesys](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/filesys.png)

OS Shell：

![shell](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/shell.png)

屏幕截图：

![screenshot](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/screenshot.png)

hashdump：

![hashdump](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/hashdump.png)

其他的在console中输入help就可以查看所有的功能命令，攻击功能可使用aliases命令查看，剩下的功能呢就交给大家去挖掘了

![aliases](http://reverse-tcp.xyz/static/img/_posts/FuzzBunch/aliases.png)

-----

2017.04.19更新 测试过程截图使用最早泄漏出来的版本，后续小伙伴们在测试时可能用了老外在Github上的[更新版本](https://github.com/misterch0c/shadowbroker)，与以上测试过程截图稍有差异，遂进行了此次更新。另外感谢Sanr表哥指导～



 











