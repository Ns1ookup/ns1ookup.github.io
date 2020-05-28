# Spring MVC 目录穿越漏洞(CVE-2018-1271)分析

## 1. 概述

### 漏洞简介
2018年04月05日，Pivotal公布了Spring MVC存在一个目录穿越漏洞(CVE-2018-1271)。Spring Framework版本5.0到5.0.4,4.3到4.3.14以及较旧的不受支持的版本允许应用程序配置Spring MVC以提供静态资源（例如CSS，JS，图像）。当Spring MVC的静态资源存放在Windows系统上时，攻击可以通过构造特殊URL导致目录遍历漏洞。


### 影响版本
- Spring Framework 5.0 to 5.0.4.
- Spring Framework 4.3 to 4.3.14
- 旧版本仍然受影响


### 利用条件

1. Windows系统
1. 要使用file协议打开资源文件目录


## 2.环境搭建

1）下载spring-mvc-showcase文件 

https://github.com/spring-projects/spring-mvc-showcase.git

2）修改 Spring MVC 静态资源配置，org.springframework.samples.mvc.config.WebMvcConfig添加如下代码：

    registry.addResourceHandler("/resources/**").addResourceLocations("file:./src/main/resources/","/resources/");

![](https://i.imgur.com/AN07FIB.png)


3）打开IDEA，选择Edit Configurations。创建Maven配置，命令行配置"jetty:run"

![](https://i.imgur.com/Pog02Dk.png)


4) 运行项目即可，项目默认端口8080，运行失败可能是端口冲突。
![](https://i.imgur.com/DUen8IU.png)


5）漏洞payload如下，进行复现测试：

    /%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini

![](https://i.imgur.com/IFkB1dE.png)


## 3.漏洞分析

当外部要访问静态资源时，会调用org.springframework.web.servlet.resource.ResourceHttpRequestHandler下的handleRequest来处理，在此处下断点调试
![](https://i.imgur.com/iKWaVPY.png)

跟进getResource方法，可以看到对path进行两次isInvalidPath判断。一次直接判断，一次是进行URL解码后进行判断。
![](https://i.imgur.com/ZAb6TPY.png)

跟进isInvalidPath函数，对path进行".."判断后，未通过"../"的判断，返回false。通过getResource方法中的第一个isInvalidPath判断
![](https://i.imgur.com/2iDkl9L.png)

接着对path进行解码，进行第二次isInvalidPath判断。继续跟进，经过cleanPath返回被处理后的path路径//windows/win.ini，最后结果返回false。进入cleanPath函数分析
![](https://i.imgur.com/RvLmk2y.png)

先对"\"进行了替换，转换为"/"
![](https://i.imgur.com/ZnoLxN0.png)

通过反斜杠将路径拆分为数组，并通过循环删除".."
![](https://i.imgur.com/DnZnZ7X.png)

执行最后的返回结果，返回路径为//windows/win.ini
![](https://i.imgur.com/XgTERc2.png)

回到getResource方法，跟进resolveResource。最终进入getResource

![](https://i.imgur.com/r1zeOqb.png)

再次进入getResource方法进行分析
![](https://i.imgur.com/MvtzkJB.png)

此处需要进行exists()和isReadable()判断，继续进入
![](https://i.imgur.com/E20CeiF.png)

文件进行exists()判断，返回true
![](https://i.imgur.com/vSGO09q.png)

在函数isReadable()中进行isFileURL判断。可以看到协议为file，满足条件
![](https://i.imgur.com/ipm2haR.png)

回到isReadable()，最终返回了ture。那么getResource返回了路径

    file:src/main/resources/%5c%5c..%5c/..%5c/..%5c/..%5c/..%5c/..%5c/..%5c/..%5c/..%5c/windows/win.ini
![](https://i.imgur.com/uj9cz1X.png)

执行完毕，回到handleRequest。最后执行到write,输出最后的结果
![](https://i.imgur.com/oHYwx9I.png)

![](https://i.imgur.com/NWE8c8E.png)

## 4.补丁修复分析
修改pom.xml文件中org.springframework-version为5.0.6.RELEASE，该版本为修复版
![](https://i.imgur.com/FPv04gG.png)

重新运行项目，原本的第二次isInvalidPath修改为isInvalidEncodedPath
![](https://i.imgur.com/T1eXgT4.png)
isInvalidEncodedPath方法直接进行cleanPath方法处理，造成对包含"../"的判断返回false
![](https://i.imgur.com/FBk2qdI.png)
接着对解码后的path进行isInvalidPath判断。包含"../",返回true
![](https://i.imgur.com/Ar4mTLc.png)

由于返回true,getResource返回null。
![](https://i.imgur.com/hmK30eg.png)

最终返回404页面

![](https://i.imgur.com/7TPRTpo.png)

## 5.修复建议

- Spring Framework 5.*（5.0到5.0.4）版本，建议更新到5.0.5版本
- Spring Framework 4.3.*（4.3到4.3.14）版本，建议更新到4.3.15版本
- 不再受支持的旧版本，建议更新到4.3.15版本或5.0.5版本


## 6.参考链接

https://paper.seebug.org/665/