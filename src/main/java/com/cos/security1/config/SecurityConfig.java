package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.security1.oauth.PrincipalOauth2UserService;

/**
 * OAuth2
 * 1. 코드받기 (인증)
 * 2. 엑세스토큰 (권한)
 * 3. 사용자프로필 정보를 가져온다.
 * 4-1. 그 정보를 토대로 회원가입을 자동으로 진행하기도 함
 * 4-2. Default 정보말고 추가 정보도 넣는다.
 */

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화
public class SecurityConfig {
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
    @SuppressWarnings("deprecation")
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        
        http.authorizeRequests() 
            .antMatchers("/user/**").authenticated()
            .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
            .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
            .anyRequest().permitAll()
            
            .and()
            .formLogin()
            .loginPage("/loginForm")
            .loginProcessingUrl("/login") // /login	주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 해줌
            .defaultSuccessUrl("/")
            
            .and()
            .oauth2Login()
            .loginPage("/loginForm")
            .userInfoEndpoint()
            .userService(principalOauth2UserService) // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip. 코드X, (엑세스토큰 + 사용자프로필정보 O) 
            
        ;
        return http.build();
        
    }
	
}
