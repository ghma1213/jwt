package com.cos.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "cos";
    String ISSUER = "magh";
    int EXPIRATION_TIME = 30000;
    int REFRESH_EXPIRATION_TIME = 300000;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
