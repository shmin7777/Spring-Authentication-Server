package com.example.auth.service;

import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.auth.domain.dto.LoginDto;
import com.example.auth.domain.dto.SignupDto;
import com.example.auth.domain.dto.TokenDto;
import com.example.auth.domain.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.jwt.JwtProperties;
import com.example.auth.security.jwt.JwtProvider;
import com.example.auth.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisService redisService;

    /**
     * 회원가입
     * 
     * @param signupDto
     */
    @Transactional
    public void registerUser(SignupDto signupDto) {
        String encodePassword = passwordEncoder.encode(signupDto.getPassword());
        User user = User.registerUser(SignupDto.encodePassword(signupDto, encodePassword));
        userRepository.save(user);
    }

    /**
     * login
     * 
     * @param loginDto
     * @return
     */
    public TokenDto login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(),
                        loginDto.getPassword());
        AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject();
        Authentication authentication = authenticationManager.authenticate(authenticationToken); // 인증

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String email = authentication.getName();
        String authorities = getAuthorities(authentication);

        return generateToken(email, authorities);
    }

    /**
     * Redis에서 RT가 있다면 DELETE, Token create & Redis에 RT 저장
     * 
     * @param email
     * @param authorities
     * @return
     */
    private TokenDto generateToken(String email, String authorities) {
        // RT가 이미 있을 경우
        if (redisService.getValues(JwtProperties.RT + email) != null) {
            redisService.deleteValue(JwtProperties.RT + email);
        }

        TokenDto tokenDto = jwtProvider.createToken(email, authorities);
        saveRefreshToken(email, tokenDto.getRefreshToken());
        return tokenDto;
    }

    /**
     * redis에 refreshToken 저장
     * 
     * @param refreshToken
     */
    @Transactional
    private void saveRefreshToken(String principal, String refreshToken) {
        redisService.setValuesWithTimeout(JwtProperties.RT + principal, refreshToken,
                JwtProperties.REFRESH_TOKEN_TTL);
    }

    /**
     * 권한 이름 가져오기
     * 
     * @param authentication
     * @return
     */
    private String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    /**
     * logout
     * 
     * @param accessToken
     */
    public void logout(String accessToken) {
        accessToken = JwtUtils.resolveToken(accessToken);
        String principal = jwtProvider.getAuthentication(accessToken).getName();

        // Redis에 저장되어있는 RT 삭제
        if (redisService.getValues(JwtProperties.RT + principal) != null) {
            redisService.deleteValue(JwtProperties.RT + principal);
        }

    }



    /**
     * token 재발급`
     * 
     * @param accessToken
     * @param refreshToken
     * @return
     */
    public TokenDto reissue(String accessToken, String refreshToken) {
        accessToken = JwtUtils.resolveToken(accessToken);
        Authentication authentication = jwtProvider.getAuthentication(accessToken);
        String principal = authentication.getName();

        String refreshTokenInRedis = redisService.getValues(JwtProperties.RT + principal);
        if (refreshTokenInRedis == null) {
            // Redis에 RT가 없는 경우 -> 재로그인 요청
            return null;
        }

        // RT의 유효성 검사 & Redis에 저장된 RT와 같은지 비교
        // 같지 않다면 삭제, 재로그인 요청
        if (!jwtProvider.validationToken(refreshTokenInRedis)
                || !refreshTokenInRedis.equals(refreshToken)) {
            redisService.deleteValue(JwtProperties.RT + principal);
            return null;
        }


        // 토큰 재발급 및 Redis 업데이트
        redisService.deleteValue(JwtProperties.RT + principal);
        TokenDto tokenDto = jwtProvider.createToken(principal, getAuthorities(authentication));
        saveRefreshToken(principal, tokenDto.getRefreshToken());
        return tokenDto;
    }


}
