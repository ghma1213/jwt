package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
        System.out.println("============================================");
        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도를 한다.

        // 3. authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 가 호출되어 loadUserByUsername() 함수 실행된다.

        // 4. PrincipalDetails 를 세션에 담고 -> 세션에 담지 않으면 권한관리가 안된다. (권한이 필요 없다면 세션에 담지 않아도 된다.)

        // 5. JWT 토큰을 만들어서 응답
        try {
            ObjectMapper om = new ObjectMapper();
            User user = null;
            user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행된다.
            // DB에 있는 username 과 password 가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);


            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 = " + principalDetails.getUser().getUsername()); // 로그인이 되었다는 뜻

            // authentication 객체가 session 영역에 저장됨
            // 권한 관리를 security 가 대신 해주기 때문에 편하다.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음.
            // 권한 처리 때문에 session을 넣어 준다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("인즈 완료");
        super.successfulAuthentication(request, response, chain, authResult);
    }


}
