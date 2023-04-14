package com.example.auth.security.jwt;


public class JwtProperties {
    public static final String SECRET =
            "a8c099efe6bca567075392cb9c59d8dc15cafaa52e423fc535c5da9e261e05d01f7bf0b1bc7679dee7ddc8c9b82b1f2fcb9241aec6addf906558f57549eee174";
    public static final String USER_ID = "userId";
    public static final String TYPE = "typ";
    public static final String TYPE_VALUE = "HS256";
    public static final String ALGORITHM = "alg";
    public static final String ALGORITHM_VALUE = "JWT";
    public static final String ROLE = "role";
    public static final String BEARER_PREFIX = "Bearer ";

    public static final int COOKIE_TTL = (1000 * 60) * 60 * 24; // 1일
    public static final long ACCESS_TOKEN_TTL = (1000 * 60) * 30; // 30분
    public static final long REFRESH_TOKEN_TTL = (60 * 1000) * 60 * 24 * 7; // 7일
    // public static final long REFRESH_TOKEN_TTL = (5 * 1000) ; // 7일

    public static final String RT = "Refresh-token: ";

    // logout
    public static final String LOGOUT = "logout";



}
