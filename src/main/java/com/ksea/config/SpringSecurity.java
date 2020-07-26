package com.ksea.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author :KSea
 * @description :
 * @createDate :2020/7/25
 */
@EnableWebSecurity
public class SpringSecurity extends WebSecurityConfigurerAdapter {
    //设置哪些角色可以访问
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                //为什么文件路径不需要/views呢
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //记住我
        http.rememberMe().rememberMeParameter("remember");
        //访问没有权限时跳转
        http.formLogin()
            .loginPage("/toLogin")
                .loginProcessingUrl("/usr/login")
                .passwordParameter("password")
                .usernameParameter("username");
        //注销
        http.logout().logoutSuccessUrl("/");
        //
        http.csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("admin").password(new BCryptPasswordEncoder().encode("admin")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("user").password(new BCryptPasswordEncoder().encode("user")).roles("vip1");

    }
}
