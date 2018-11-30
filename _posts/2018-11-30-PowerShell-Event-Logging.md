---
layout: post
title: 围绕PowerShell事件日志记录的攻防博弈战
date: 2018-11-30 13:43:02
categories: [Blue Team, Red Team, PowerShell]
---

> 本文首发[绿盟科技技术博客](http://blog.nsfocus.net/attacks-defenses-powershell-event-logging/)

### 0x00 简介

PowerShell一直是网络攻防对抗中关注的热点技术，其具备的无文件特性、LotL特性以及良好的易用性使其广泛使用于各类攻击场景。为了捕获利用PowerShell的攻击行为，越来越多的安全从业人员使用PowerShell事件日志进行日志分析，提取Post-Exploitation等攻击记录，进行企业安全的监测预警、分析溯源及取证工作。随之而来，如何躲避事件日志记录成为攻防博弈的重要一环，围绕PowerShell事件查看器不断改善的安全特性，攻击者利用多种技巧与方法破坏PowerShell日志工具自身数据，以及事件记录的完整性。今年10月份微软发布补丁的CVE-2018-8415正是再次突破PowerShell事件查看器记录的又一方法，本文将细数PowerShell各大版本的日志功能安全特性，及针对其版本的攻击手段，品析攻防博弈中的攻击思路与技巧。


### 0x01 PowerShell攻防简介

PowerShell是一种功能强大的脚本语言和shell程序框架，主要用于Windows计算机方便管理员进行系统管理并有可能在未来取代Windows上的默认命令提示符。PowerShell脚本因其良好的功能特性常用于正常的系统管理和安全配置工作，然而，这些特性被攻击者理解并转化为攻击特性（见下），也成为了攻击者手中的利器，给企业网络造成威胁。
PowerShell攻击特性总结：

- **无文件攻击特性防查杀**，可躲避防火墙、众多反病毒软件和入侵防御系统：PowerShell的无文件特性，使其无需接触磁盘，内存直接加载并执行恶意代码。
- **具备LotL攻击特性**，攻击者轻松达到攻击目的的同时躲避常见的攻击检测和入侵防御系统：PowerShell在众多Windows操作系统中是默认安装的，这类系统自带的、受信任的工具，反恶意软件极难检测和限制，使攻击者无需增加额外的二进制文件，有效的躲避了常见的攻击检测和入侵防御系统。
- **极易混淆编码**，PowerShell具备脚本类语言的特点，灵活多变，很容易配合多种混淆方法，对抗传统检测工具
- **良好的功能及适应性**，满足多种攻击场景的需求：PowerShell内置远程管理机制，可用于远程命令执行；PowerShell支持WMI和.NET Framework，极易使用。

自2005年微软发布PowerShell以来，在这13年的攻防对抗的过程中，微软曾多次改善powershell的安全性问题，使PowerShell的攻击环境越来越严苛，其中很重要的一项措施就是PowerShell的ScriptBlock日志记录功能，他可以完整的记录PowerShell的历史执行过程，当然这是有助于进行攻击取证和溯源的。然而，攻防对抗是一个此消彼长、长期博弈的过程，安全对抗技术的研究也一直关注着PowerShell日志的脆弱性和记录绕过方法，在今年7月份国外的安全研究员@Malwrologist就发现了PowerShell日志记录模块存在一处缺陷，攻击者可使用空字符对日志进行截断，导致重要日志缺失，微软在本月的补丁更新中修复了该问题，漏洞编号**CVE-2018-8415**。

**RT&BT视角下的PowerShell的日志功能**

在分析此漏洞前我们先以RT&BT视角总结一下PowerShell的日志功能，让我们回顾PowerShell历代版本的防御思路与攻击手段

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell-event-logging-sec.png)

### 0x02 初代的PowerShell v2

> PowerShell v2提供事件记录能力，可以协助蓝队进行相关的攻击事件推断和关联性分析，但是其日志记录单一，相关Post-Exploitation可做到无痕迹；并且因为系统兼容性，在后续版本攻击者都会尝试降级至此版本去躲避日志记录。

作为PowerShell的初代版本，微软提供了PowerShell基础的事件记录能力，能进行一些简单的事件记录，但是在执行日志记录方面的能力表现不尽理想。尽管如此，旧版本中的默认日志记录级别也可以提供足够的证据来识别PowerShell使用情况，将远程处理与本地活动区分开来并提供诸如会话持续时间和相关用户帐户之类的上下文，这些已经可以帮助位于防御方的蓝队人员进行相关的攻击事件推断和关联性分析。

**防御角度（蓝队视角）：**

在执行任何PowerShell命令或脚本时，无论是本地还是通过远程处理，Windows都可以将事件写入以下三个日志文件：

• Windows PowerShell.evtx 

• Microsoft-Windows-PowerShell/Operational.evtx

• Microsoft-Windows-PowerShell/Analytic.etl

 

由于PowerShell通过Windows远程管理（WinRM）服务实现其远程处理功能，因此以下两个事件日志还捕获远程PowerShell活动：

• Microsoft-Windows-WinRM/Operational.evtx

• Microsoft-Windows-WinRM/Analytic.etl

 

通常PowerShell 2.0事件日志可以提供命令活动或脚本执行的开始和停止时间，加载的提供程序（指示正在使用的功能类型）以及发生活动的用户帐户。它们不提供所有已执行命令或其输出的详细历史记录。Analytic日志记录了更多的信息，可以帮助我们定位一些错误是在什么地方发生的，但Analytic日志如果启用（默认情况下禁用）在生产环境中将产生大量记录数据可能会妨碍实际分析。

分析日志可以在事件查看器菜单栏中的查看选项点击“显示分析和调试日志”显示，并在Microsoft-Windows-WinRM/Analytic中选择“启用日志”开启，也可以通过wevtutil Set-Log命令开启：

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell-analytic.png)

以下部分总结了与PowerShell 2.0相关的每种事件日志捕获的重要证据。

**Windows PowerShell.evtx**

每次在PowerShell执行单个命令时，不管是本地会话还是远程会话都会产生以下日志：

• 事件ID 400：引擎状态从无更改为可用，记录任何本地或远程PowerShell活动的开始；

• 事件ID 600：记录类似“WSMan”等提供程序在系统上进行PowerShell处理活动的开始，比如”Provider WSMan Is Started“；

• 事件ID 403：引擎状态从可用状态更改为停止，记录PowerShell活动结束。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell-evtx.png)

EID 400和EID 403事件的消息详细信息包括HostName字段。如果在本地执行，则此字段将记录为HostName = ConsoleHost。如果正在使用PowerShell远程处理，则访问的系统将使用HostName = ServerRemoteHost记录这些事件。

两条消息都不记录与PowerShell活动关联的用户帐户。但是，通过使用这些事件，分析人员可以确定PowerShell会话的持续时间，以及它是在本地运行还是通过远程运行。

**Microsoft-Windows-PowerShell/Operational.evtx**

在使用PowerShell 2.0时，该日志记录还未发现有实质的记录情况。

**Microsoft-Windows-WinRM/Operational.evtx**

WinRM操作日志记录Windows远程管理服务的所有使用，包括通过PowerShell远程处理进行的操作。

• 事件ID 6：在客户端系统上的远程处理活动开始时记录。包括系统连接的目标地址；

• 事件ID 169：在访问系统的远程处理活动开始时记录。包括用于访问WinRM的用户名和身份验证机制；

• 事件ID 142：如果远程服务器禁用了WinRM，则客户端在尝试启动远程Shell连接时将产生该记录；

**Microsoft-Windows-PowerShell/Analytic.etl**

如之前所讲，分析日志必须开启才能捕获事件，并且用于故障排除而不是长期的安全审计。处于活动状态时，涉及远程命令执行安全相关的事件ID如下：

• 事件ID 32850：记录为远程处理进行身份验证的用户帐户；

• 事件ID 32867/32868：记录在PowerShell远程处理期间进行的每个PowerShell输入和输出对象，包括协议和版本协商以及命令I / O对象在表示为“有效负载数据”的字段中存储为XML编码的十六进制字符串，并且到期长度通常在多个日志消息中分段。

• 事件ID 142：如果远程服务器禁用了WinRM，则客户端在尝试启动远程Shell连接时将产生该记录；

**Microsoft-Windows-WinRM/Analytic.etl**

与PowerShell分析日志记录类似，默认情况下不启用WinRM分析日志记录，一旦配置，它就会生成大量事件，这些事件再次被编码并且难以分析。

**攻击角度（红队视角）：**

由于日志记录的单一性，最初进行的各种PowerShell相关Post-Exploitation基本是无痕迹的，即使在后续更高的版本中，由于版本向前的兼容性，系统具备启用PowerShell2.0的功能，攻击者也常通过*powershell -version 2*命令将PowerShell Command-line切换至v2版本去躲避日志记录，有点“降级攻击”的意思。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell2.0Engine.png)

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershellv2-attack.png)

### 0x03 PowerShell v3/v4 全面的日志记录

> PowerShell v3/v4相比之前提供了更全面的日志记录功能，这个时期，攻击手段转变为利用混淆手段模糊日志记录，躲避识别检测。

借助对 Windows 事件跟踪 (ETW) 日志、模块中可编辑的 LogPipelineExecutionDetails属性和“打开模块日志记录”组策略设置的支持，Windows PowerShell 3.0 改进了对命令和模块的日志记录和跟踪支持。 自PowerShell v3版本以后支持启用PowerShell模块日志记录功能，并将此类日志归属到了4103事件。

PowerShell模块日志可以配置为记录所有的PowerShell模块的活动情况，包括单一的PowerShell命令、导入的模块、远程管理等。可以通过GPO进行启用模块日志记录。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell-module-logging.png)

或者设置以下注册表项具有相同的效果：

```
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging → EnableModuleLogging = 1

HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging \ModuleNames → * = *
```

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/powershell4103logging.png)

模块日志记录了PowerShell脚本或命令执行过程中的CommandInvocation类型和ParameterBlinding内容，涉及执行过程和输入输出内容，模块日志功能的加入几乎可以完整的记录下PowerShell执行日志，给日志分析预警监测带来了极大的方便。

从攻防发展的历史来看，此版本出现后攻击者也考虑了其他方式来躲避日志记录，比如使用大量的混淆算法来进行模糊处理。

### 0x04 PowerShell v5 提供反混淆功能

> PowerShell v5加入了CLM和ScriptBlock日志记录功能，能去混淆PowerShell代码并记录到事件日志，有效的抵御之前的攻击手段，这个时期，攻击思路更多的体现在如何降级到PowerShell v2版本

随着PowerShell攻击技术的不断成熟，攻击者为了规避防护和日志记录进行了大量的代码混淆，在执行代码之前很难发现或确认这些代码实际上会做些什么事情，给攻击检测和取证造成了一定的困难，因此微软从PowerShell5.0开始加入了日志转储、ScriptBlock日志记录功能，并将其归入到事件4104当中，ScriptBlock Logging提供了在事件日志中记录反混淆的 PowerShell 代码的能力。

由于脚本代码在执行之前需要进行反混淆处理，ScriptBLock日志就会在实际的代码传递到 PowerShell 引擎执行之前进行记录，所以在很多的集中化日志系统一旦捕捉到可疑的日志时就能够及时的进行告警，当然个人觉得在样本分析应急取证方面也可以进行利用。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/scriptblock-logging.png)

启用脚本块日志可以以管理员权限运行PowerShell v5，并运行以下命令即可：

```powershell
Install-Module -Name scriptblocklogginganalyzer -Scope CurrentUser
set-SBLLogSize -MaxSizeMB 1000
Enalbe-SBL
```

或者通过GPO启用PowerShell脚本块日志记录功能并记录脚本文件的调用信息：

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/GPO-scriptblock.png)

当然也可以通过修改以下注册表选项来开启：

```
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1
```

PowerShell 5.0支持Windows7/2008 R2及更高版本的操作系统。虽然PowerShell 5.0的许多增强日志记录功能都被反向移植到4.0版，但还是建议在所有Windows平台上安装PowerShell 5.0。 PowerShell 5.0包含4.0中未提供的功能，包括可疑的脚本块日志记录。

### 0x05 PowerShell v6 新的攻击面pwsh

> PowerShell v6出于功能需求，提供了更全面的系统覆盖能力，同时也暴露了新的攻击面——pwsh

由于PowerShell在Linux和MacOS等操作系统上的支持在MacOS上安装（pwsh），处于安全性考虑日志记录作为必不可少的一部分，PowerShell使用本机os_log API登录Apple的统一日志记录系统。在Linux上，PowerShell使用Syslog，微软将此上升成为一种几乎全平台支持的日志记录解决方案。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/pwsh-logging.png)

**攻击思路（红队视角）：**powershell加入其他系统当中在给管理员带来便利的同时无疑也增大了这些系统的攻击面，而且在现有最新版本中日志记录方面也并没有做的特别到位，我在进行相关测试的时候发现若PowerShell执行报错就会有日志产生，但程序正常执行没有报错的情况下，syslog中只会存在“PowerShell console is starting up”和“PowerShell console is ready for user input”，比如进行简单反向shell就又多了一种方法，且并未记录到本地执行反弹PWSH的操作。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/pwsh-reverse-shell.png)

### 0x06 CVE-2018-8415 日志记录绕过漏洞

> *A tampering vulnerability exists in PowerShell that could allow an attacker to execute unlogged code.To exploit this vulnerability, an attacker would need to log on to the affected system and run a specially crafted application.The security update addresses the vulnerability by correcting log management of special characters.*

微软对此漏洞的描述和评定为重要（未到严重级别），利用此漏洞，攻击者通过构造代码可以绕过我们上述所描述的脚本块日志记录功能。通过github上的补丁描述，此漏洞影响PowerShell核心全版本（包括pwsh等），补丁修复方案只是以unicode方式将\u0000替换成了\u2400。如下图所示，从补丁中的这段注释已经可以推测此漏洞的原理了，简单来说，就是空字符截断导致ScriptBlock日志对命令记录时发生了异常终止了记录。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/CVE-2018-8415-patch.png)

漏洞发现者@Malwrologist早在7月就曾在自己的twitter上就对该问题进行了披露，我们根据作者思路对漏洞进行复现，发现该漏洞由于空字符限制只能在脚本运行时生效，Command-line环境由于自身限制导致是无法依靠单一的PowerShell命令完成漏洞利用的，当然同样也发现在命令拼接的多条命令执行中4103事件日志无法完美截断，单一的键值内容还是会被记录下来。

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/CVE-2018-8415-null.png)

![](http://reverse-tcp.xyz/static/img/posts/powershell-Event-logging/CVE-2018-8415-4103event.png)

**攻击思路（红队视角）：**虽然此漏洞利用后还会有键值内容被记录下来，但实际攻击场景中攻击脚本代码为了实现相关功能都具备复杂的执行逻辑，再者由于4103事件日志不具备反混淆记录的能力，想要从大量的混淆键值记录数据中还原脚本功能和攻击意图会产生很高的分析成本，因此该漏洞依旧具有很好的攻击利用价值。

### 0x07 总结

PowerShell其实已经被广泛运用于不同规模的攻击活动，无论是下载器中、内网横向扩展中、权限维持系统后门中，甚至MuddyWater、[FruityArmor](https://twitter.com/hashtag/FruityArmor?src=hash)等多个APT组织的攻击事件中都被使用，可以预见再未来几年仍是攻击热点技术。PowerShell事件日志作为企业在此方面进行监测预警的重要数据支持必须充分发挥作用，建议企业用户保持PowerShell事件查看器处于最新版本，并启用ScriptBlock日志等功能来加强防御。

绿盟科技伏影实验室-模因战队将持续跟踪分析最新的攻防对抗技术和威胁风险，非常欢迎对各类攻防对抗技术感兴趣的同学与我们进行交流！

### 0x08 参考文章

<https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/>

<https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8415>

<https://github.com/PowerShell/PowerShell/pull/8253>

<https://twitter.com/DissectMalware/status/1016462916059631616>

 