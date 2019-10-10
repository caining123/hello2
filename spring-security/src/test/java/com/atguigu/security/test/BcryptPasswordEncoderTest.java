package com.atguigu.security.test;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BcryptPasswordEncoderTest {

	@Test
	public void test() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		//$2a$10$OoCNL6wegDodC4tES//8E.Jz//yzrX57PXCB.gFFRJO5z7/k58B6W
		//$2a$10$zA1IsErSKB8uf1Ni45bVq.wFQ/55RYBH4XsUFpdm8.4Ubgu.HEESi
		//$2a$10$Mz5LhpIcbm6IFpaLMV.WRO3Mr1mJ0Hcp524bQNN7qe2GPy4.t/XEG
		//$2a$10$5eAARs4N./lKnwO8P.KNzOQIXZGq9uiCKsGu3tjv/hpNre8.AMpUu
		System.out.println(encoder.encode("qazwsx"));
	}

}
