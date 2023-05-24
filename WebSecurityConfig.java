package com.seneca.template.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.seneca.template.auth.AuthJWTEntryPoint;
import com.seneca.template.auth.AuthJWTTokenFilter;
import com.seneca.template.services.JWTUserDetailService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Autowired
	AuthJWTTokenFilter authJWTTokenfilter;

	@Autowired
	AuthJWTEntryPoint authJWTEntryPoint;

	@Autowired
	JWTUserDetailService jwtUserDetailService;

	final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		try {
			http.csrf().disable();
			http.authorizeHttpRequests((requests) -> requests.antMatchers(HttpMethod.POST, "/auth/signin").permitAll()
					 .antMatchers("/actuator/**").permitAll()
					.anyRequest().authenticated()).formLogin((form) -> form.loginPage("/login").permitAll())
					.logout((logout) -> logout.permitAll()).exceptionHandling()
					.authenticationEntryPoint(authJWTEntryPoint).and()
					.addFilterBefore(authJWTTokenfilter, UsernamePasswordAuthenticationFilter.class);
			return http.build();
		} catch (Exception exp) {
			if (logger.isErrorEnabled()) {
				logger.error("Error while configuring http ", exp);
			}
		}
		return null;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean(HttpSecurity http) {
		try {
			AuthenticationManagerBuilder authenticationManagerBuilder = http
					.getSharedObject(AuthenticationManagerBuilder.class);
			authenticationManagerBuilder.userDetailsService(jwtUserDetailService)
					.passwordEncoder(bCryptPasswordEncoder());
			return authenticationManagerBuilder.build();
		} catch (Exception exp) {
			if (logger.isErrorEnabled()) {
				logger.error("Error while configuring http ", exp);
			}
		}
		return null;
	}
}
