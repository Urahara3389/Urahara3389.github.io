---
layout:     post
title:      "Apache Struts2 Remote Code Execution (S2-052) "
date:       2017-09-07
categories: [Struts2, Remote Code Execution, Java Security]

---

### Versions Affected

```
Struts 2.1.2 - Struts 2.3.33,
Struts 2.5 - Struts 2.5.12
```

### Description

根据官方漏洞描述，Struts2 REST插件在使用XStreamHandler反序列化XStream实例的时候没有对类进行任何限制，导致将xml数据转换成Object时产生远程代码执行漏洞（RCE）。同时，官方的解决方案是将Struts2的版本升级至2.5.13 或 2.3.34，那么先对比一下官方的版本升级代码，发现`struts-2.5-2.13\src\plugins\rest\src\main\java\org\apache\struts2\rest\handler\XStreamHandler.java`对类进行了一些白名单处理。

![whitelist](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-whitelist.png)

除了使用[com.thoughtworks.xstream.security](http://x-stream.github.io/javadoc/com/thoughtworks/xstream/security/package-summary.html)中的类进行[TypePermission](http://x-stream.github.io/javadoc/com/thoughtworks/xstream/security/TypePermission.html)外，还定义了CollectionTypePermission类进行了限制，只有Collection及Map的子类才被允许，这样就限制了XStream在进行xml->object过程当中传入的危险类。

![CollectionTypePermission](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-CollectionTypePermission.png)

### Vulnerability Analysis

目前公布的POC基本是基于[marshalsec](https://github.com/mbechler/marshalsec)来生成的，而且还没有回显，marshalsec支持XStream反序列化POC的共计11个`[SpringPartiallyComparableAdvisorHolder, SpringAbstractBeanFactoryPointcutAdvisor, Rome, XBean, Resin, CommonsConfiguration, LazySearchEnumeration, BindingEnumeration, ServiceLoader, ImageIO, CommonsBeanutils]`，其中利用ImageIO能直接执行系统命令，而像ServiceLoader等就可以进行SSRF等操作，甚至远程加载自定义类进行命令执行等。

![ImageIO](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-ImageIO.png)

![ssrf](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-ssrf.png)

通常用rest-plugin是为了开发rest-service，对于 REST 架构的服务器端而言，它提供的是资源，但同一资源具有多种表现形式，REST 风格的资源能以 XHTML、XML 和 JSON 三种形式存在，其中 XML 格式的数据是 WebServices 技术的数据交换格式，而 JSON 则是另一种轻量级的数据交换格式；至于 XHTML 格式则主要由浏览器负责呈现。而在struts2 rest-plugin 中的处理逻辑是判断content-type的内容，再调用对应handler.toObject方法对其进行实例化。

![handler.toObject](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-handler.toObject.png)

在这个漏洞中，出现问题的是处理xml时产生的安全问题，所以最终调用的是——`XStreamHandler`的`toObject`方法，这个补丁代码是一致的，在`XStreamHandler`中的`xstream.fromXML(in, target)`处下断点，这是开始xml->object的入口

![XStreamHandler](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-XStreamHandler.png)

最后跟进到`unmarshal`，这里其实就是最终进行反序列化的地方了，可以继续跟进但在这个漏洞这里没什么必要了，完整的调用栈如下

![unmarshal](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-unmarshal.png)

从整个过程来看，我们需要注意的是这个漏洞的触发只需要将content-type设置为`application/xml`，再发送poc即可，与请求方式和请求链接无关，这种情况是比较通用的。而还有一种情况是在请求类似于`/struts2-rest-showcase/orders/5/update.xml`这种xml资源时，需要设置content-type为`delicious/bookmark+xml`，这在[xxlegend](http://xxlegend.com/)的分析POC中有体现，struts2官方发的相关缓解措施也是无效的。

![poc](http://reverse-tcp.xyz/static/img/posts/struts2/s2-052-poc.png)

### Solution

就此漏洞而言暂时没有什么可靠的临时方案，进行版本升级对类进行白名单限制才是根本。





