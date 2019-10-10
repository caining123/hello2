package com.atguigu.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

//注意： 开发中使用springsecurity 
//1、pom文件引入依赖 
//2、在web.xml配置springsecurity filter -
//3、编写springsecurity配置类：在配置类中编写权限验证规则... 
//4、在controller中方法上可以使用 @PreAuthorize("hasAnyRole('ADMIN')") 对方法进行授权绑定

@Controller
public class GongfuController {

	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/level1/1")
	public String leve11Page() {
		return "/level1/1";
	}

	@PreAuthorize("hasAnyRole('MANAGER','GL - 组长')")
	@GetMapping("/level1/2")
	public String leve12Page() {
		return "/level1/2";
	}

	@PreAuthorize("hasAnyAuthority('user:delete','user:add')")
	@GetMapping("/level1/3")
	public String leve13Page() {
		return "/level1/3";
	}

	@GetMapping("/level2/{path}")
	public String leve2Page(@PathVariable("path") String path) {
		return "/level2/" + path;
	}

	@GetMapping("/level3/{path}")
	public String leve3Page(@PathVariable("path") String path) {
		return "/level3/" + path;
	}

}
