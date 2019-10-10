package com.atguigu.security.config;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.atguigu.security.service.MD5Util;

//自定义的密码处理器
public class AppMD5PasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		// 可以使用自己的加密方法对传入的密码进行加密处理

		return MD5Util.digest(rawPassword.toString());
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String loginPwd = encode(rawPassword);
		return loginPwd.equals(encodedPassword);
	}

}
