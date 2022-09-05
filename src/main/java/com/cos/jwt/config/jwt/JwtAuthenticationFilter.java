package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username, password 전송하면(POST)
// UsernamePasswordAuthenticationFilter 동작 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
    // 인증 요청시에 실행되는 함수 => /login
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 진입");

        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도를 한다.

        // 3. authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 가 호출되어 loadUserByUsername() 함수 실행된다.

        // 4. PrincipalDetails 를 세션에 담고 -> 세션에 담지 않으면 권한관리가 안된다. (권한이 필요 없다면 세션에 담지 않아도 된다.)

        // 5. JWT 토큰을 만들어서 응답
        return super.attemptAuthentication(request, response);
    }

}
