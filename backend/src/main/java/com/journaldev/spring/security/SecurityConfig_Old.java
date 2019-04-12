package com.journaldev.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//@Configuration
//@EnableWebSecurity
public class SecurityConfig_Old extends WebSecurityConfigurerAdapter {

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {
		// @formatter:off
		authenticationMgr
			.inMemoryAuthentication().passwordEncoder(passwordEncoder)
				.withUser("user").password(passwordEncoder.encode("password")).authorities("ROLE_USER");
		// @formatter:on

	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
