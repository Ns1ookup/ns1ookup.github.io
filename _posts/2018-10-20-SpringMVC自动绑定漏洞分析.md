# Spring MVC Autobinding漏洞分析

##1.概述

Autobinding-自动绑定漏洞，根据不同语言/框架，该漏洞有几个不同的叫法，如下：

- Mass Assignment: Ruby on Rails, NodeJS
- Autobinding: Spring MVC, ASP.NET MVC
- Object injection: PHP(对象注入、反序列化漏洞)

软件框架有时允许开发人员自动将HTTP请求参数绑定到程序代码变量或对象中，从而使开发人员更容易地使用该框架。这里攻击者就可以利用这种方法通过构造http请求，将请求参数绑定到对象上，当代码逻辑使用该对象参数时就可能产生一些不可预料的结果。

##2.Java中的注解

###2.1 @ModelAttribute
注解@ModelAttribute是一个非常常用的注解，其功能主要在两方面：

- 运用在参数上，会将客户端传递过来的参数按名称注入到指定对象中，并且会将这个对象自动加入ModelMap中，便于View层使用；
- 运用在方法上，会在每一个@RequestMapping标注的方法前执行，如果有返回值，则自动将该返回值加入到ModelMap中；

**注解的作用：**

当使用表单传值得时候，如果定义了name，address，age等属性。通过表单传过去的值就只有这3个属性，但用户账号信息是name，pass，address，age四个属性。那么在提交表单并赋值的时候就会出现，未得到的值为null的情况。如下图：
![](https://i.imgur.com/2CSNPIx.png)

这时的信息就会变成

![](https://i.imgur.com/tx20gju.png)

需要用@ModelAttribute注解来解决这个问题：

    @ModelAttribute
    public void getUsers(@RequestParam(value="name",required=false) String name,Map<String, Object> map){
     if(name!=null){
      System.out.println("调用ModelAttribute");
      //模拟从数据库中获取的对象。
      User users = new User("cjh","123","123@qq.com","China");
      System.out.println("从数据库中获取一个对象"+users);
      map.put("user",users);
     }
    }
    @RequestMapping("/getInfo")
    public String getServletAPI(User user){
     String viewName = "hello";
     System.out.println("修改："+user);
     return viewName;
    }


@ModelAttribute注解运用在方法上，会在每一个@RequestMapping标注的方法前执行，如果有返回值，则自动将该返回值加入到ModelMap中。同时，在当前的控制器中任何一个方法都会被调用。

以上代码的运行流程为：

1. 首先执行@ModelAttribute注解修饰的方法，从数据库中查找出对应要修改的对象，把值放在map键值对中，key应该和处理请求的方法传入的参数名一样。
1. Spring MVC会从Map中找出user对象，并把表单请求参数赋值给该user对象，只有表单定义了的属性才会被替换，没定义的为null,不改变。所以要求@ModelAttribute修饰的方法中定义的key的名称要和控制器方法（@RequestMapping()修饰的方法）中入参的名称要一致。否则没效果。
1. Spring MVC 把上述对象传入目标方法的参数。

输出结果如下：
![](https://i.imgur.com/vdzsfVn.png)

###2.2@SessionAttributes
在默认情况下，ModelMap 中的属性作用域是 request 级别，也就是说，当本次请求结束后，ModelMap 中的属性将销毁。如果希望在多个请求中共享 ModelMap 中的属性，必须将其属性转存到 session 中，这样 ModelMap 的属性才可以被跨请求访问。

Spring 允许我们有选择地指定 ModelMap 中的哪些属性需要转存到 session 中，以便下一个请求对应的 ModelMap 的属性列表中还能访问到这些属性。这一功能是通过类定义处标注 @SessionAttributes("user") 注解来实现的。SpringMVC 就会自动将 @SessionAttributes 定义的属性注入到 ModelMap 对象，在 setup action 的参数列表时，去 ModelMap 中取到这样的对象，再添加到参数列表。只要不去调用 SessionStatus 的 setComplete() 方法，这个对象就会一直保留在 Session 中，从而实现 Session 信息的共享


##3.案例分析
下载测试环境：https://github.com/GrrrDog/ZeroNights-HackQuest-2016

将war包部署在tomcat的webapps中，菜单栏有about，reg，Sign up，Forgot password这4个页面组成。
![](https://i.imgur.com/80FbVVD.png)

进入Forgot password页面,请求路径/rest。分析控制器ResetPasswordController的代码，对输入的username进行判断
![](https://i.imgur.com/rLp7k30.png)

从UserService中获取到构造方法中自定义的user数据
![](https://i.imgur.com/0XayHyt.png)

从参数获取username并检查有没有这个用户，如果有则把这个user对象放到Model中。因为这个Controller使用了@SessionAttributes("user")，所以同时也会自动把user对象放到session中。
![](https://i.imgur.com/9Azehe0.png)

然后跳转到resetQuestion密码找回安全问题校验页面。由于之前已经将user对象放入session,此处进行判断的user对象就是存储的对象。
![](https://i.imgur.com/L3otZzE.png)

这个时候，从User的JavaBean中我们知道了安全问题的参数为answer
![](https://i.imgur.com/J2yx4PX.png)

通过请求resetQuestion页面，我们不仅可以修改answer参数，还可以修改提升权限的参数isSupaAdministrata。
![](https://i.imgur.com/AUP2TD8.png)
修改成功，打印输出的日志信息如下：
![](https://i.imgur.com/hfYpa98.png)

##4.安全建议
Spring MVC中可以使用@InitBinder注解，通过WebDataBinder的方法setAllowedFields、setDisallowedFields设置允许或不允许绑定的参数。

##5.参考
https://www.owasp.org/index.php/Mass_Assignment_Cheat_Sheet#Spring_MVC 