package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Objects;

// 시큐리티가 filter 를 가지고 있는데, 그 필터 중에 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청됨");
        String header = request.getHeader(JwtProperties.HEADER_STRING);
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        System.out.println("header : " + header);
        String token = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        DecodedJWT decode = JWT.decode(token);
        String payload = decode.getPayload();

        // 토큰 검증 (이게 인증이기 때문에 AuthenticationManager도 필요 없음)
        // 내가 SecurityContext에 집적접근해서 세션을 만들때 자동으로 UserDetailsService에 있는
        // loadByUsername이 호출됨.
        User user;
//        try {
            String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).withIssuer(JwtProperties.ISSUER).build().verify(token)
                    .getClaim("username").asString();

            if (username != null) {
                 user = userRepository.findByUsername(username);

                // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
                // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
                PrincipalDetails principalDetails = new PrincipalDetails(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                        null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                        principalDetails.getAuthorities());

                // 강제로 시큐리티의 세션에 접근하여 값 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
//        } catch (TokenExpiredException e) {
//            System.out.println("e = " + e);
//            refreshTokenCheck(Objects.requireNonNull(user), request, response, chain);
//        }


        chain.doFilter(request, response);
    }

    private void refreshTokenCheck(User user, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        String refreshToken = user.getRefreshToken();
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).withIssuer(JwtProperties.ISSUER).build().verify(refreshToken)
                .getClaim("username").asString();
        if (username != null) {
            String jwtToken = JWT.create()
                    .withIssuer(JwtProperties.ISSUER)
                    .withSubject(user.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                    .withClaim("id", user.getId())
                    .withClaim("username", user.getUsername())
                    .sign(Algorithm.HMAC512(JwtProperties.SECRET));

            response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
            try {
                chain.doFilter(request, response);
            } catch (IOException | ServletException e) {
                e.printStackTrace();
            }
        }
    }


    // 인증이나 권한이 필요한 주소는 이 필터를 탄다.
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//        System.out.println("인증이나 권한이 필요한 주소 요청됨");
//
//        String jwtHeader = request.getHeader("Authorization");
//        System.out.println("jwtHeader = " + jwtHeader);
//
//        // header 가 있는지 확인
//        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
//            chain.doFilter(request, response);
//            return;
//        }
//
//        // JWT 토큰을 검증 해서 정상적인 사용자인지 확인
//        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
//        String username = JWT.require(Algorithm.HMAC512("cos"))
//                .build().verify(jwtToken).getClaim("username").asString();
//
//        // 서명이 제대로 됨
//        if (username != null) {
//            User userEntity = userRepository.findByUsername(username);
//
//            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
//
//            // 토큰 서명을 통해서 실제 로그인이 아닌 authentication 객체 생성을 위함
//            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
//
//            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        }
//        chain.doFilter(request, response);
//    }


}

