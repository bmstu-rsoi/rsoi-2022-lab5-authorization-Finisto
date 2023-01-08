package com.finist.microservices2022.gatewaylibraryservice.config;

import com.finist.microservices2022.gatewaylibraryservice.handler.LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig {

    private final LogoutHandler logoutHandler;

    public SecurityConfig(LogoutHandler logoutHandler) {
        this.logoutHandler = logoutHandler;
    }




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.authorizeRequests()
                .mvcMatchers(HttpMethod.POST,"/login").permitAll()
                .mvcMatchers(HttpMethod.GET,"/login").permitAll()
                .anyRequest().authenticated()
//                .and().oauth2Login()
                .and().oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)

//                .and().logout()
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                .addLogoutHandler(logoutHandler)
//                .and().build();
                .build();
    }


}
