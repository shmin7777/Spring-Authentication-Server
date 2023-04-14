package com.example.auth.security.jwt;

public class JwtUtils {

    /**
     * accessToken에서 'Bearer ' 추출
     * 
     * @param accessToken
     * @return
     */
    public static String resolveToken(String accessToken) {
        if (accessToken != null && accessToken.startsWith(JwtProperties.BEARER_PREFIX)) {
            return accessToken.substring(7);
        }
        return null;
    }
}
