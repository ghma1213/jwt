package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class);
        http.csrf().disable(); // CSRF 토큰 검증 방식 사용하지 않음
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않음
                .and()
                .formLogin().disable() // formLogin 사용 X -> form tag 사용 안함
                .httpBasic().disable() // 기존 http 로그인 방식을 사용 안함 - headers에 authorization: id, pw를 담아 인증하는 방식 (bearer 토큰을 담아 인증하는 방식)
                .apply(new MyCustomDsl()) // 커스텀 필터 등록
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                ;


        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter()) // 모든 요청 전 필터를 거친다. @CrossOrigin(인증은 안됨) -> 시큐리티 필터에 등록하면 인증 된다.
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
//                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository))
                    ;
        }
    }
}
