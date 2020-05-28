# Apache Shiro 1.2.4反序列化漏洞的分析

## 一. 概述
Apache Shiro 在 Java 的权限及安全验证框架中占用重要的一席之地，在它编号为550的 issue 中爆出严重的 Java 反序列化漏洞。

## 二. 准备


**漏洞环境搭建**

漏洞项目位于/shiro/samples/web中,项目地址：https://github.com/apache/shiro.git

为了配合生成反序列化的漏洞环境，需要添加存在漏洞的 jar 包，编辑 pom.xml 文件，添加如下行：


    <!--  需要设置编译的版本 -->
     <properties>
    <maven.compiler.source>1.6</maven.compiler.source>
    <maven.compiler.target>1.6</maven.compiler.target>
    </properties>
    ...
    <dependencies>
    <dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>jstl</artifactId>
    <!--  这里需要将jstl设置为1.2 -->
    <version>1.2</version
    <scope>runtime</scope>
    </dependency>
    .....
    <dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.0</version>
    </dependency>
    <dependencies>


修改完成 pom.xml 文件后，为了打包成war包，还需在pom.xml中加入如下代码：

参考地址：https://blog.csdn.net/qq_26525215/article/details/54788514

![](https://i.imgur.com/mv6LybJ.png)

要配置一下maven，在maven/conf/toolchains.xml中的toolchains 中添加以下代码，同时需要安装jdk1.6

 
    
      <toolchain>
    
    <type>jdk</type>
    
    <provides>
    
      <version>1.6</version>
    
      <vendor>sun</vendor>
    
    </provides>
    
    <configuration>
    
      <jdkHome>C:/Program Files/Java/jdk1.6.0_45</jdkHome>
    
    </configuration>
    
      </toolchain>

在pom.xml文件所在目录下执行mvn install命令进行打包编译工程。如果出现Failed to execute goal org.apache.maven.plugins:maven-war-plugin 的错误，可参考地址：https://blog.csdn.net/a_bang/article/details/72849483

![](https://i.imgur.com/WRnonvv.png)


**Payload生成**

Java反序列化工具ysoserial，链接地址：https://github.com/frohoff/ysoserial

使用方法如下，payload为可利用的依赖库文件。选择依赖库时，注意版本信息。payload不成功的原因可能是目标依赖库版本过低。通过-h可自行选择目标服务器可利用的依赖库文件。

    java -jar ysoserial.jar [payload] '[command]'

### 三. 漏洞分析
从官方的 issue 上来看，存在几个重要的点:

- rememberMe cookie
- CookieRememberMeManager.java
- Base64
- AES
- 加密密钥硬编码
- Java serialization

我们使用已经构造好的payload进行分析

![](https://i.imgur.com/OhvWkEO.png)

打开IDEA进行远程调试，调试过程参考http://wiki.intra.tophant.com/pages/viewpage.action?pageId=20649899

先看一下org.apache.shiro.web.mgt.CookieRememberMeManager类的结构
![](https://i.imgur.com/WkWCFyP.png)
 

发现有getRememberedSerializedIdentity这个方法，从字面意思上来看跟rememberMe和序列化都有关系，在此处下断点。
![](https://i.imgur.com/bOjNHzL.png)

往下执行，传入的payload进行了base64解码
![](https://i.imgur.com/S7zGBzV.png)
跳出了该函数，发现解码后的payload传入了convertBytesToPrincipals方法，跟进该方法进行查看。
![](https://i.imgur.com/HsuntJh.png)
对payload进行了解密操作，继续跟进解密方法
![](https://i.imgur.com/bLPKhZq.png)
找到了解密的密钥，以及AES解密方法。AES的初始化向量iv就是rememberMe的base64解码后的前16个字节
![](https://i.imgur.com/FhLI4Mp.png)

![](https://i.imgur.com/fjLys0J.png)
通过查看newCipherInstance方法，发现填充模式为CBC。通过密钥和填充方式，可随意构造payload。
![](https://i.imgur.com/TmTuan0.png)

之后对序列化代码进行反序列操作，进入反序列化函数查看
![](https://i.imgur.com/zFpno6t.png)
执行到readObject，成功执行payload,弹出计算器
![](https://i.imgur.com/3oTYTVj.png)