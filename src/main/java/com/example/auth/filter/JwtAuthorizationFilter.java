package com.example.auth.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * OncePerRequestFilter : 한 요청에 대해 딱 한번만 적용되는 것을 보장하는 필터 여러 필터를 거치는 도중 redirect를 시킬 경우 다시 처음부터 필터를
 * 거쳐야되는데, OncePerRequestFilter는 한번만 실행되기 때문에 여러번의 인증을 막을 수 있음
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // TODO Auto-generated method stub
        log.info("OncePerRequestFilter in!!");
        filterChain.doFilter(request, response);
    }

}
