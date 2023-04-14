package com.example.auth.controller;

import javax.servlet.http.Cookie;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.auth.domain.dto.LoginDto;
import com.example.auth.domain.dto.SignupDto;
import com.example.auth.domain.dto.TokenDto;
import com.example.auth.security.jwt.JwtProperties;
import com.example.auth.security.jwt.JwtProvider;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthApiController {
    // https://github.com/u-nij/Authentication-Using-JWT/blob/main/src/main/java/com/example/jwt/dto/AuthDto.java#L20
    private final UserService userService;

    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody SignupDto signupDto) {
        userService.registerUser(signupDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody LoginDto loginDto) {
        log.info("login controller in!! {}", loginDto);
        TokenDto tokenDto = userService.login(loginDto);


        HttpCookie httpCookie = ResponseCookie.from("refresh-token", tokenDto.getRefreshToken())
                .maxAge(JwtProperties.COOKIE_TTL)
                .httpOnly(true) // client에서 script로 cookie 접근 제한
                .secure(true) // https가 이닌면 쿠키 전송 안함
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .header(HttpHeaders.AUTHORIZATION,
                        JwtProperties.BEARER_PREFIX + tokenDto.getAccessToken())
                .build();
    }

}
