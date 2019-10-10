package com.atguigu.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

/**
 * 1、导入练习的maven工程 2、在pom文件中导入springsecurity的依赖[3个]
 * 3、在web.xml中配置springsecurity的代理filter
 * 4、在项目中创建springsecurity的配置类继承WebSecurityConfigurerAdapter
 * 5、让配置类成为组件+启用springsecurity
 * 6、当访问项目的资源时，自动跳转到一个springsecurity自带的登录页面，则代表springsecurity已经配置成功
 * 
 * @Configuration :代表配置类注解
 * @EnableWebSecurity :代表启用webspringsecurity的注解
 * 
 *                    实验1： 项目首页/登录页面 以及项目中所有的静态资源
 *                    希望springsecurity不用授权认证，所有人都可以访问
 */

@Configuration // 代表配置类注解
@EnableWebSecurity // 代表启用webspringsecurity的注解
@EnableGlobalMethodSecurity(prePostEnabled=true)//启用更加细粒度的控制 ，控制方法映射的权限访问
public class AppSpringSecurityConfig extends WebSecurityConfigurerAdapter {

	// 控制表单提交+请求认证授权...
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// super.configure(http);//默认规则（不使用），访问时直接跳转到springsecurity的默认登录页面

		// 实验6： 基于角色和权限的访问控制
		// 自定义认证授权规则：
		// authorizeRequests() 请求授权认证
		// antMatchers() ant风格路径
		// permitAll() 允许所有人访问
		http.authorizeRequests().antMatchers("/index.jsp", "/layui/**")// 设置首页和静态资源所有人都可以访问
				.permitAll()// 设置首页所有人都可以访问
				//.antMatchers("/level1/*").hasAnyRole("SE - 软件工程师")// 给具体的资源设置需要的权限或角色
				//.antMatchers("/level2/*").hasAnyAuthority("SE - 软件工程师")// 给具体的资源设置需要的权限或角色
				//.antMatchers("/level3/*").hasAnyAuthority("USER:DELETE")// 给具体的资源设置需要的权限或角色
				.anyRequest().authenticated();// 设置其他的所有请求都需要授权认证:只要登录授权认证成功，那么就可以访问所有资源，除非资源设置了具体的权限要求
		// 实验2.1： 如果访问未授权页面，默认显示403页面， 希望给用户响应一个springsecurity默认的登录页面
		// http.formLogin();//设置给用户响应一个springsecurity默认的登录页面

		// 实验2.2： 默认登录页面由框架提供，过于简单，希望跳转到项目自带的登录页面
		// 实验3： 设置自定义的登录表单提交的action地址，注意：
		// 1、action地址和loginProcessing的Url一样
		// 2、请求方式必须是post
		// 3、springsecurity考虑安全问题表单提交必须携带token标志(防止表单重复提交、防止钓鱼网站攻击)
		http.formLogin().loginPage("/index.jsp")// 设置自定义的登录页面
				.usernameParameter("uname")// 设置登录表单的账号的name属性值,默认username
				.passwordParameter("pwd")// 设置登录表单的密码的name属性值，默认password
				.loginProcessingUrl("/dologin")// 设置提交登录请求的url地址，默认会交给springsecurity处理,相当于springMVC中处理器的@RequestMapper("")中设置的路径，
				.defaultSuccessUrl("/main.html");// 设置登录成功要跳转的页面

		// 禁用springsecurity的csrf 验证功能,框架默认开启，访问登录页面时框架会自动创建一个唯一的字符串设置到session域中
		// 如果使用csrf功能：需要在登录页面的表单中获取唯一字符串以隐藏域的形式设置，name属性值必须是:_csrf
		// http.csrf().disable();

		// 实验5：默认注销方式
		// 注意： 1、请求方式必须是post 2、csrf如果开启了必须在表单中携带csrf的token 3、默认的注销请求的url logout
		// 实验5.2： 自定义注销方式
		http.logout().logoutUrl("/user-logout")// 自定义注销url地址
				.logoutSuccessUrl("/index.jsp");// 注销成功的跳转页面

		// 实验6.2：自定义异常处理，当页面403时自动跳转到指定页面
		// http.exceptionHandling().accessDeniedPage("/unauthed");
		http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {

			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException) throws IOException, ServletException {

				// 访问失败的资源
				request.setAttribute("resource", request.getServletPath());

				// 访问失败的异常信息
				request.setAttribute("errorMsg", accessDeniedException.getMessage());

				// 请求转发到自定义页面
				request.getRequestDispatcher("/unauthed").forward(request, response);

			}
		});

		// 实验7：记住我简单版[登录请求携带 remeber-me 参数 ， 代码中开启remeberme功能]
		// 用户登录成功，主体信息(用户信息+权限角色信息)默认保存在服务器内存的session中，一次会话有效
		// 如果希望登录之后的主体权限角色信息范围超过一次会话，可以开启springsecurity的记住我功能
		// http.rememberMe();
		// 浏览器会接受到springsecurity创建的remeberme的token持久化保存，下次打开浏览器只要携带token就可以访问之前有权访问的页面
		// 服务器将token对应的权限信息存在服务器内存中，如果服务器重启 则失效[浏览器记住我功能失效了]
		// 实验7-2：记住我数据库版

		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);// 配置数据源，可以操作数据库
		http.rememberMe().tokenRepository(tokenRepository);
	}

	@Autowired
	javax.sql.DataSource dataSource;

	@Autowired
	UserDetailsService userDetailsService;

	@Autowired
	PasswordEncoder passwordEncoder;

	// PasswordEncoder passwordEncoder = new AppMD5PasswordEncoder();

	// 认证： 设置验证的账号密码+ 该用户的角色权限...
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// 实验4：自定义用户信息
		// auth.inMemoryAuthentication()// 在内存中设置账号密码+授权
		// .withUser("a").password("1")// 设置单个用户的用户名+密码 //创建主体时：包含用户账号密码+角色权限列表
		// .roles("MANAGER")// 赋予用户角色
		// .and()// 设置第2个用户的用户名+密码
		// .withUser("b").password("2").authorities("USER:ADD")// 设置角色权限
		// .and()// 设置第3个用户的用户名+密码
		// .withUser("c").password("3").authorities("USER:DELETE");// 设置角色权限
		// roles("ADMIN")和authorities("USER","MANAGER")区别
		// 一个是以用户拥有角色进行认证，一个是以用户拥有权限进行验证；这两种都是认证的权限。
		// 设置角色权限时，无论调用roles还是authorities，底层都是调用了authorities实现的
		// role传入的字符串前默认会拼接：ROLE_前缀 表示角色 ,底层判断角色权限时本质是进行字符串比较

		// 实验8-1：基于数据库数据的认证[登录信息和数据库数据进行比较、登录成功用户的权限角色从数据库中获取]

		// 如果使用UserDetailsService 框架提供的实现类来完整主体信息的查询封装，表必须和它要求的一样
		// 这里我们使用自己创建的表，所以要新建一个UserDetailsService接口的实现类
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	// 向容器中配置bean的方式：
	// 1、在spring配置文件中使用<bean>标签配置
	// 2、在组件上使用组件注解配置 Component、Repository(Mapper)、Service、Controller、Configuration
	// 3、在方法上使用@Bean注解配置
	// 标注的方法返回值会自动交给容器配置到容器中 、方法必须写在组件中

	@Bean
	public BCryptPasswordEncoder getPasswordEncoder11111() {
		return new BCryptPasswordEncoder();
	}
}
