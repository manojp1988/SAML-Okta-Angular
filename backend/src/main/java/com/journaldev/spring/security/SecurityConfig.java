package com.journaldev.spring.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.journaldev.spring.security.jwt.JwtAuthenticationFilter;
import com.journaldev.spring.security.jwt.JwtAuthenticationProvider;

/**
 * @author slemoine
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("authorization", "content-type", "x-auth-token"));
        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

	@Configuration
	@Order(1)
	public static class FormAuthSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private BCryptPasswordEncoder passwordEncoder;

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off 
			auth
				.inMemoryAuthentication().passwordEncoder(this.passwordEncoder)
					.withUser("username")
						.password(this.passwordEncoder.encode("password")).roles("USER");
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling().
					authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				.and()
					.cors().and().csrf().disable()
					.antMatcher("/auth/formLogin")
					.authorizeRequests()
						.antMatchers("/auth/formLogin").permitAll()
						.anyRequest().authenticated()
				.and()
					.logout().logoutUrl("/auth/logout");
			// @formatter:on
		}

		@Bean
		public BCryptPasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}
	}

	@Configuration
	@Order(2)
	public static class RestApiSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/api/**";

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.cors().and()
				.addFilterBefore(new JwtAuthenticationFilter(apiMatcher, super.authenticationManager()), UsernamePasswordAuthenticationFilter.class)
				.antMatcher(apiMatcher).authorizeRequests()
					.anyRequest().authenticated();			 
			// @formatter:on

		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			auth.authenticationProvider(new JwtAuthenticationProvider());
		}
	}

	@Configuration
	@Order(3)
	public static class AuthSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String apiMatcher = "/auth/token";

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// @formatter:off
			http
				.exceptionHandling()
					.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				.and()
					.antMatcher(apiMatcher).authorizeRequests().anyRequest().authenticated();			 
			// @formatter:on

		}
	}

	@Configuration
	@Import(SamlSecurityConfig.class)
	public static class SamlConfig {

	}

}
