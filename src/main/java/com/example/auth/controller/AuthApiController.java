package com.example.auth.controller;

import javax.servlet.http.Cookie;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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
    private final UserService userService;
    private final JwtProvider jwtProvider;

    /**
     * 회원가입 api
     * 
     * @param signupDto
     * @return
     */
    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody SignupDto signupDto) {
        userService.registerUser(signupDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * login api header : refresh-token(RT) cookie, header : Authorization : Bearer + accessToken
     * 
     * @param loginDto
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody LoginDto loginDto) {
        log.info("login controller in!! {}", loginDto);
        TokenDto tokenDto = userService.login(loginDto);


        HttpCookie httpCookie = ResponseCookie.from("refresh-token", tokenDto.getRefreshToken())
                .maxAge(JwtProperties.COOKIE_TTL)
                .httpOnly(true) // client에서 script로 cookie 접근 제한
                // .secure(true) // https가 이닌면 쿠키 전송 안함
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .header(HttpHeaders.AUTHORIZATION,
                        JwtProperties.BEARER_PREFIX + tokenDto.getAccessToken())
                .build();
    }

    /**
     * accessToken이 정상적이면 200, 아니면 401
     * 
     * @param accessToken
     * @return
     */
    @GetMapping("/check/acess-token")
    public ResponseEntity<Void> checkAcessToken(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION) String accessToken) {
        if (jwtProvider.validationToken(accessToken)) {
            return ResponseEntity.status(HttpStatus.OK).build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    // reissue: validate 요청으로부터 UNAUTHORIZED(401)을 반환받았다면,
    // 프론트에서 Cookie와 Header에 각각 RT와 AT를 요청으로 받아서 authService.reissue를 통해 토큰 재발급을 진행한다.
    // 토큰 재발급이 성공한다면 login과 마찬가지로 응답 결과를 보내고,
    // 토큰 재발급이 실패했을때(null을 반환받았을 때) Cookie에 담긴 RT를 삭제하고 재로그인을 유도한다.

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION) String accessTokenr,
            @CookieValue("refresh-token") String refreshToken) {
        TokenDto tokenDto = userService.reissue(accessTokenr, refreshToken);
        if (tokenDto != null) { // 토큰 재발급 성공
            HttpCookie httpCookie = ResponseCookie.from("refresh-token", tokenDto.getRefreshToken())
                    .maxAge(JwtProperties.COOKIE_TTL)
                    .httpOnly(true) // client에서 script로 cookie 접근 제한
                    // .secure(true) // https가 이닌면 쿠키 전송 안함
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                    .header(HttpHeaders.AUTHORIZATION,
                            JwtProperties.BEARER_PREFIX + tokenDto.getAccessToken())
                    .build();
        } else {
            HttpCookie httpCookie = ResponseCookie.from("refresh-token", "")
                    .maxAge(0)
                    .path("/") // 모든 경로에 cookie를 사용하게 함
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                    .build();
        }

    }

    /**
     * Cookie에 담긴 RT 삭제
     * 
     * @param accessToken
     * @return
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION) String accessToken) {
        userService.logout(accessToken);

        HttpCookie httpCookie = ResponseCookie.from("refresh-token", "")
                .maxAge(0)
                .path("/") // 모든 경로에 cookie를 사용하게 함
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .build();
    }

}
