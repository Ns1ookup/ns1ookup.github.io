# 前言

Codeql是一款非常优秀的代码审计工具，支持对C++，C#，Java，JavaScript，Python，go等多种语言进行分析，可用于分析代码，查找代码中控制流等信息。目前要对Codeql的代码审计流程梳理成技术文档，除了基础语法之外，针对常规应用漏洞也需要编写ql语法文档。

一方面是对技术的总结梳理，另一方面也是作为技术手册提升团队代码审计能力，挖掘更多有价值的漏洞。由于内部项目基本为Java，前期的手册还是以Java代码审计为主。后期会尝试做Python和JavaScript的梳理，这两种语言生成DB文件不需要进行编译，相对Java是方便很多。

在Blog上应该只会分享的XSS笔记，代码审计的手册不会分享



## 代码审计 

### 代码中的漏洞

以javasec项目为例(https://github.com/JoyChou93/java-sec-code)，项目中XSS漏洞接口的代码如下：

```
@Controller
@RequestMapping("/xss")
public class XSS {

    /**
     * Vuln Code.
     * ReflectXSS
     * http://localhost:8080/xss/reflect?xss=<script>alert(1)</script>
     *
     * @param xss unescape string
     */
    @RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return xss;
    }

    /**
     * Vul Code.
     * StoredXSS Step1
     * http://localhost:8080/xss/stored/store?xss=<script>alert(1)</script>
     *
     * @param xss unescape string
     */
    @RequestMapping("/stored/store")
    @ResponseBody
    public String store(String xss, HttpServletResponse response) {
        Cookie cookie = new Cookie("xss", xss);
        response.addCookie(cookie);
        return "Set param into cookie";
    }

    /**
     * Vul Code.
     * StoredXSS Step2
     * http://localhost:8080/xss/stored/show
     *
     * @param xss unescape string
     */
    @RequestMapping("/stored/show")
    @ResponseBody
    public String show(@CookieValue("xss") String xss) {
        return xss;
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return encode(xss);
    }

    private static String encode(String origin) {
        origin = StringUtils.replace(origin, "&", "&amp;");
        origin = StringUtils.replace(origin, "<", "&lt;");
        origin = StringUtils.replace(origin, ">", "&gt;");
        origin = StringUtils.replace(origin, "\"", "&quot;");
        origin = StringUtils.replace(origin, "'", "&#x27;");
        origin = StringUtils.replace(origin, "/", "&#x2F;");
        return origin;
    }
}

```

首先我们关注反射型XSS，存在反射型的XSS的API接口为 `/xss/reflect`。可以看到存在漏洞的api接口是将请求参数直接return，但是不存在XSS的接口会对参数做替换处理，同样返回替换后的参数值。



### 传统代码审计工具检测

以开源项目cobra为例，检测XSS的规则配置为：

```
<?xml version="1.0" encoding="UTF-8"?>
<cobra document="https://github.com/WhaleShark-Team/cobra">
    <name value="输出入参可能导致XSS"/>
    <language value="java"/>
    <match mode="regex-only-match"><![CDATA[out\.println\s*\(\s*request\.get(Parameter|QueryString)\s*\(\s*\"]]></match>
    <level value="4"/>
    <solution>
        ## 安全风险
        输出入参会导致XSS

        ## 修复方案
        使用Begis对参数进行过滤后再输出
    </solution>
    <test>
        <case assert="true"><![CDATA[out.println(request.getParameter("test"))]]></case>
    </test>
    <status value="on"/>
    <author name="Feei" email="feei@feei.cn"/>
</cobra>

```



可以看到上面规则中Java代码的XSS检测是通过正则匹配实现，并且只能识别 `out.println(request.getParameter("test"))` 场景下的漏洞代码。很明显不能检测Spring MVC架构中的漏洞代码。即使增加如下/reflect接口 漏洞代码检测的规则，也会将safe接口作为漏洞检测出来。所以误报率非常高

```
@RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return xss;
    }
    
/**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return encode(xss);
    }

    private static String encode(String origin) {
        origin = StringUtils.replace(origin, "&", "&amp;");
        origin = StringUtils.replace(origin, "<", "&lt;");
        origin = StringUtils.replace(origin, ">", "&gt;");
        origin = StringUtils.replace(origin, "\"", "&quot;");
        origin = StringUtils.replace(origin, "'", "&#x27;");
        origin = StringUtils.replace(origin, "/", "&#x2F;");
        return origin;
    }
```



### 漏洞代码特征

单纯从漏洞触发点来看，依旧会有非常多的误报信息。通过Codeql来检索，我们可以考虑静态污点分析的方式来降低误报率。通过扩展 TaintTracking::Configuration 类来使用全局污染跟踪库

**Source**

用户输入的可控参数 (通常是Request对象获取的参数)

**Sink**

不经过编码输出的数据 (但输出污点的方法不同，不同的开发架构中也不同)



仅仅是完成上述的sink和source，依然会有很多误报出现。污点的传播过程需要加入限制条件来降低误报率，例如 Sanitizer、AdditionalTaintStep。



### Codeql XSS规则

官方已经提供了比较通用的XSS检测规则，代码如下：

```
/**
 * @name Cross-site scripting
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/xss
 * @tags security
 *       external/cwe/cwe-079
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.XSS
import DataFlow::PathGraph

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof XssSanitizer }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  } 
}

from DataFlow::PathNode source, DataFlow::PathNode sink, XSSConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"

```

#### 规则分析

可以看到在isSource这个函数的定义中，使用了Codeql已经封装好了RemoteFlowSource，官方文档的解释为：

- A data flow source of remote user input.(远程用户输入的数据流)

```
override predicate isSource(DataFlow::Node source) {
	 source instanceof RemoteFlowSource 
}
```



接着看isSink这个函数的定义，同样使用了Codeql已经封装好的XssSink，官方文档的解释为：

- A sink that represent a method that outputs data without applying contextual output encoding.(输出数据且不经过上下文编码的方法)

```
 override predicate isSink(DataFlow::Node sink) { 
	sink instanceof XssSink 
}
```



除此之外，增加了isSanitizer和isAdditionalTaintStep两个函数。分别代表着

- A sanitizer that neutralizes dangerous characters that can be used to perform a XSS attack.(拦截用于XSS攻击语句的过滤器)
- A unit class for adding additional taint steps.(添加污点步骤的class类)



**XssSink**

DefaultXssSink类继承了抽象类XssSink，在构造方法中实现了对Sink的定义。有下面几种关键类：

- HttpServletResponseSendErrorMethod：The method sendError(int,String) declared in     javax.servlet.http.HttpServletResponse.  (javax.servlet.http.HttpServletResponse中定义的sendEoor方法)

- ServletWriterSourceToWritingMethodFlowConfig (编写的ServletWriteSource到WritingMethod的数据传播链):

  ```java
  private class ServletWriterSourceToWritingMethodFlowConfig extends TaintTracking2::Configuration {
    ServletWriterSourceToWritingMethodFlowConfig() {
      this = "XSS::ServletWriterSourceToWritingMethodFlowConfig"
    }
  
    override predicate isSource(DataFlow::Node src) { src.asExpr() instanceof ServletWriterSource }
  
    override predicate isSink(DataFlow::Node sink) {
      exists(MethodAccess ma |
        sink.asExpr() = ma.getQualifier() and ma.getMethod() instanceof WritingMethod
      )
    }
  }
  
  private class WritingMethod extends Method {
    WritingMethod() {
      getDeclaringType().getASupertype*().hasQualifiedName("java.io", _) and
      (
        this.getName().matches("print%") or
        this.getName() = "append" or
        this.getName() = "format" or
        this.getName() = "write"
      )
    }
  }
  ```

- TypeWebView：指的是Android中的webview
- SpringRequestMappingMethod：A method  on a Spring controller that is executed in response to a web request. （Spring 中控制器controller执行response输出的方法）



```
/** A sink that represent a method that outputs data without applying contextual output encoding. */
abstract class XssSink extends DataFlow::Node { }

/** A default sink representing methods susceptible to XSS attacks. */
private class DefaultXssSink extends XssSink {
  DefaultXssSink() {
    exists(HttpServletResponseSendErrorMethod m, MethodAccess ma |
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(1)
    )
    or
    exists(ServletWriterSourceToWritingMethodFlowConfig writer, MethodAccess ma |
      ma.getMethod() instanceof WritingMethod and
      writer.hasFlowToExpr(ma.getQualifier()) and
      this.asExpr() = ma.getArgument(_)
    )
    or
    exists(Method m |
      m.getDeclaringType() instanceof TypeWebView and
      (
        m.getAReference().getArgument(0) = this.asExpr() and m.getName() = "loadData"
        or
        m.getAReference().getArgument(0) = this.asExpr() and m.getName() = "loadUrl"
        or
        m.getAReference().getArgument(1) = this.asExpr() and m.getName() = "loadDataWithBaseURL"
      )
    )
    or
    exists(SpringRequestMappingMethod requestMappingMethod, ReturnStmt rs |
      requestMappingMethod = rs.getEnclosingCallable() and
      this.asExpr() = rs.getResult() and
      (
        not exists(requestMappingMethod.getProduces()) or
        requestMappingMethod.getProduces().matches("text/%")
      )
    |
      // If a Spring request mapping method is either annotated with @ResponseBody (or equivalent),
      // or returns a HttpEntity or sub-type, then the return value of the method is converted into
      // a HTTP reponse using a HttpMessageConverter implementation. The implementation is chosen
      // based on the return type of the method, and the Accept header of the request.
      //
      // By default, the only message converter which produces a response which is vulnerable to
      // XSS is the StringHttpMessageConverter, which "Accept"s all text/* content types, including
      // text/html. Therefore, if a browser request includes "text/html" in the "Accept" header,
      // any String returned will be converted into a text/html response.
      requestMappingMethod.isResponseBody() and
      requestMappingMethod.getReturnType() instanceof TypeString
      or
      exists(Type returnType |
        // A return type of HttpEntity<T> or ResponseEntity<T> represents an HTTP response with both
        // a body and a set of headers. The body is subject to the same HttpMessageConverter
        // process as above.
        returnType = requestMappingMethod.getReturnType() and
        (
          returnType instanceof SpringHttpEntity
          or
          returnType instanceof SpringResponseEntity
        )
      |
        // The type argument, representing the type of the body, is type String
        returnType.(ParameterizedClass).getTypeArgument(0) instanceof TypeString
        or
        // Return type is a Raw class, which means no static type information on the body. In this
        // case we will still treat this as an XSS sink, but rely on our taint flow steps for
        // HttpEntity/ResponseEntity to only pass taint into those instances if the body type was
        // String.
        returnType instanceof RawClass
      )
    )
  }
}
```



**XssSanitizer**

DefaultXSSSanitizer继承了抽象类XssSanitizer，在构造方法中实现了对Sanitizer的定义。该类的构造方法实现了对当前节点的类型判断：

 

- NumericType：A  numeric type, including both primitive and boxed types.(数字类型参数，包括原始类型和包装类型。例如：int/Integer)
- BooleanType：A  boolean type, which may be either a primitive or a boxed type.(布尔类型，可以是原始类型或者包装类型，如boolean/Boolean)

```
/** A sanitizer that neutralizes dangerous characters that can be used to perform a XSS attack. */
abstract class XssSanitizer extends DataFlow::Node { }

/** A default sanitizer that considers numeric and boolean typed data safe for writing to output. */
private class DefaultXSSSanitizer extends XssSanitizer {
  DefaultXSSSanitizer() {
    this.getType() instanceof NumericType or this.getType() instanceof BooleanType
  }
}
```



**XssAdditionalTaintStep**

XssAdditionalTaintStep类继承了Unit类，根据描述是保留存在从节点1到节点2，且存在XSS污点配置的步骤

```
class XssAdditionalTaintStep extends Unit {
  /**
   * Holds if the step from `node1` to `node2` should be considered a taint
   * step for XSS taint configurations.
   */
  abstract predicate step(DataFlow::Node node1, DataFlow::Node node2);
}
```

接下来使用默认的XSS规则进行检测，查看检出情况。XSS接口中的反射XSS均被检出，不存在误报情况。

![13](C:\Users\halo.liu\Documents\GitHub\ns1ookup.github.io\_posts\codeql_photo\13.png)

![13](C:\Users\halo.liu\Documents\GitHub\ns1ookup.github.io\_posts\codeql_photo\14.png)

除了原本存在XSS漏洞接口，SSRF/Cookies/IPForge接口均被检出反射型XSS漏洞。

![13](C:\Users\halo.liu\Documents\GitHub\ns1ookup.github.io\_posts\codeql_photo\15.png)



#### 规则定义

针对XSS漏洞的污点检测，Source可以固定不变。Sink在不同的架构中有不同的定义方式，`semmle.code.java.security.XSS` 模块中已经提供了比较多的场景。如需自定义Sink，继承抽象类XssSink。并写入Sink条件

```
/** A sink that represent a method that outputs data without applying contextual output encoding. */
abstract class XssSink extends DataFlow::Node { }

/** A default sink representing methods susceptible to XSS attacks. */
private class DefineXssSink extends XssSink {
  DefineXssSink() {
    exists( xxx | xxx )
  }
}
```



