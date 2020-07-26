# security

## 引入依赖
```xml
   <dependency>
         <groupId>org.springframework.boot</groupId>
         <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
```

## 实现方法

- 编写配置类，继承WebSecurityConfigurerAdapter
- 重写protected void configure(HttpSecurity http)，用于设置授权规则，即设置文件的访问权限角色
    - http.formLogin(); 设置登录
    - http.logout().logoutUrl("/");  设置注销
    - http.csrf().disable(); 关闭防跨域
    - http.rememberMe();  开启记住我
    - 各种参数可以进源码看注释 
- 重写protected void configure(AuthenticationManagerBuilder auth) ，用于设置认证规则，即给用户分配角色
- 报错500，密码需要设置加密方式
- 结合命名空间sec，可以判断登录状态与非登录状态时显示不同的内容