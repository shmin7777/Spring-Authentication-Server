package com.example.auth.security.jwt;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.example.auth.domain.dto.TokenDto;
import com.example.auth.security.PrincipalDetails;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtProvider {

    private Key getSigninKey() {
        byte[] keyBytes = JwtProperties.SECRET.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto generateToken(Authentication authentication) {
        log.info(authentication.getPrincipal().toString());
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        String email = principalDetails.getUsername();
        String authorities = principalDetails.getUser().getRole().getKey();
        long now = System.currentTimeMillis();

        String accessToken = Jwts.builder()
                .setHeaderParam(JwtProperties.TYPE, JwtProperties.TYPE_VALUE)
                .setHeaderParam(JwtProperties.ALGORITHM, JwtProperties.ALGORITHM_VALUE)
                .setExpiration(new Date(now + JwtProperties.ACCESS_TOKEN_TTL))
                .setSubject("access-token")
                .claim(JwtProperties.USER_ID, email)
                .claim(JwtProperties.ROLE, authorities)
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();

        log.info("accessToken :: {}", accessToken);

        String refreshToken = Jwts.builder()
                .setHeaderParam(JwtProperties.TYPE, JwtProperties.TYPE_VALUE)
                .setHeaderParam(JwtProperties.ALGORITHM, JwtProperties.ALGORITHM_VALUE)
                .setExpiration(new Date(now + JwtProperties.REFRESH_TOKEN_TTL))
                .setSubject("refresh-token")
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();

        log.info("token dto generated !!");

        return new TokenDto(accessToken, refreshToken);
    }

    public boolean validationAccessToken(String accessToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigninKey()).build()
                    .parseClaimsJws(accessToken); // 파싱 및 검증 , 실패 시 error
            return true;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return false;
        }

    }
}
