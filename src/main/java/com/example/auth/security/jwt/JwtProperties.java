package com.example.auth.security.jwt;


public class JwtProperties {
    public static final String SECRET = "hong";
    public static final String USER_ID = "userId";
    public static final String TYPE = "typ";
    public static final String TYPE_VALUE = "HS256";
    public static final String ALGORITHM = "alg";
    public static final String ALGORITHM_VALUE = "JWT";
    public static final String ROLE = "role";
    public static final String BEARER_PREFIX = "Bearer ";
    
    public static final int COOKIE_TTL = (1000 * 60) * 60 * 24; // 1일
    public static final long ACCESS_TOKEN_TTL =  (1000 * 60) * 30; // 30분
    public static final long REFRESH_TOKEN_TTL =  (60 * 1000) * 60 * 24 * 7; // 7일
    
    
    
}
