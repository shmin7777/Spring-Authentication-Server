package com.example.auth.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.auth.security.jwt.JwtProperties;
import com.example.auth.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * OncePerRequestFilter : 한 요청에 대해 딱 한번만 적용되는 것을 보장하는 필터 여러 필터를 거치는 도중 redirect를 시킬 경우 다시 처음부터 필터를
 * 거쳐야되는데, OncePerRequestFilter는 한번만 실행되기 때문에 여러번의 인증을 막을 수 있음
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // TODO Auto-generated method stub
        log.info("OncePerRequestFilter in!!");
        String accessToken = resolveToken(request);

        // 정상 토큰인지 검사
        try {
            if (accessToken != null && jwtProvider.validationAccessToken(accessToken)) {
                log.info("정상적인 토큰입니다!!");
            }

        } catch (Exception e) {
            log.error("잘못된 토큰입니다 :: {} ", e);
            response.sendError(403);
        }

        filterChain.doFilter(request, response);

    }

    // HTTP Request 헤더로부터 토큰 추출
    public String resolveToken(HttpServletRequest httpServletRequest) {
        String bearerToken = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(JwtProperties.BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
