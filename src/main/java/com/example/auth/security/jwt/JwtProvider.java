package com.example.auth.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import com.example.auth.domain.dto.TokenDto;
import com.example.auth.security.PrincipalDetails;
import com.example.auth.service.RedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final UserDetailsService userDetailsService;
    private final RedisService redisService;

    /**
     * secret key hashing
     * 
     * @return
     */
    private Key getSigninKey() {
        byte[] keyBytes = JwtProperties.SECRET.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto createToken(String email, String authorities) {
        long now = System.currentTimeMillis();

        String accessToken = createAccessToken(email, authorities, now);

        log.info("accessToken :: {}", accessToken);

        String refreshToken = createRefreshToken(email, authorities, now);

        log.info("token dto generated !!");

        return new TokenDto(accessToken, refreshToken);
    }

    /**
     * access token create
     * 
     * @param email
     * @param authorities
     * @param now
     * @return
     */
    public String createAccessToken(String email, String authorities, long now) {
        return Jwts.builder()
                .setHeaderParam(JwtProperties.TYPE, JwtProperties.TYPE_VALUE)
                .setHeaderParam(JwtProperties.ALGORITHM, JwtProperties.ALGORITHM_VALUE)
                .setExpiration(new Date(now + JwtProperties.ACCESS_TOKEN_TTL))
                .setSubject("access-token")
                .claim(JwtProperties.USER_ID, email)
                .claim(JwtProperties.ROLE, authorities)
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * refresh token create
     * 
     * @param email
     * @param authorities
     * @param now
     * @return
     */
    public String createRefreshToken(String email, String authorities, long now) {
        return Jwts.builder()
                .setHeaderParam(JwtProperties.TYPE, JwtProperties.TYPE_VALUE)
                .setHeaderParam(JwtProperties.ALGORITHM, JwtProperties.ALGORITHM_VALUE)
                .setExpiration(new Date(now + JwtProperties.REFRESH_TOKEN_TTL))
                .setSubject("refresh-token")
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * token validation 파싱 및 검증
     * 
     * @param accessToken
     * @return
     */
    public boolean validationToken(String token) {
        try {
            token = token.replace(JwtProperties.BEARER_PREFIX, "");

            Jwts.parserBuilder()
                    .setSigningKey(getSigninKey()).build()
                    .parseClaimsJws(token); // 파싱 및 검증 , 실패 시 error
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            return false;
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
            return false;
        }
    }


    /**
     * token으로 Authentication을 가져옴
     * 
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        String email = getPrincipal(token);
        PrincipalDetails principalDetails =
                (PrincipalDetails) userDetailsService.loadUserByUsername(email);
        return new UsernamePasswordAuthenticationToken(principalDetails.getUsername(),
                principalDetails.getPassword(), principalDetails.getAuthorities());
    }

    /**
     * token으로부터 principal 얻음
     * 
     * @param token
     * @return
     */
    private String getPrincipal(String token) {
        return getClaims(token).get(JwtProperties.USER_ID).toString();
    }

    /**
     * Claim을 가져옴
     * 
     * @param token
     * @return
     */
    private Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigninKey()).build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * token의 만료 시간
     * 
     * @param token
     * @return
     */
    private long getExpireTime(String token) {
        return getClaims(token).getExpiration().getTime();
    }

    /**
     * token의 만료시간이 지났는지 검사
     * 
     * @param token
     * @return
     */
    private boolean validationTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
