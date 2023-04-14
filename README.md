# Spring-Authentication-Server  
![image](https://user-images.githubusercontent.com/67637716/231922596-ba2d907f-feca-4ccd-990b-c54046f1e903.png)  

Spring Security, JWT, Redis를 사용하여 인증서버 구축

* Redis
https://github.com/shmin7777/Spring-Redis    

* JWT
https://github.com/shmin7777/spring-jwt  

* Security
https://github.com/shmin7777/spring-security  



## 동작방식  
`SecurityConfig.class` : formLogin, httpBasic disable, session 사용 안함, `JwtAuthorizationFilter` 등록, cors 허용 

`/api/mypage/**` : 인증 필요
`/api/admin/**` : ROLE_ADMIN 권한만 인증됨  

Redis에 RefreshToken 저장. RefreshToken은 항상 AccessToken보다 만료시간 김.  


* /login 
UsernamePasswordAuthenticationToken을 만들어 AuthenticationManager.authentication()으로 인증.  
인증 후 JWT 토큰을 만들고 토큰 return.  
Redis에 RefreshToken 저장.  
header에 `AUTHORIZATION` : accessToken, Cookie : refresh token return.   

* /check/acess-token : AT validation  
accessToken이 유효한지 확인 후 정상이면 200, 아니면 401 return

* /reissue : 토큰 재발급
 401을 반환받았다면 AT, RT를 요청으로 받아 재발급을한다.  
 Redis에 RT가 없거나 유효성 검사 후 재로그인 요청  
 Validation 통과 -> Redis에서 RT update.  
 AT, RT return.  
 
 * /logout
Redis에있는 RT 삭제.  
쿠키 삭제.  

* JwtAuthorizationFilter 
권한 인증 필터  
OncePerRequestFilter : 한 요청에 대해 딱 한번만 적용되는 것을 보장하는 필터 여러 필터를 거치는 도중 redirect를 시킬 경우 다시 처음부터 필터를 거쳐야되는데, OncePerRequestFilter는 한번만 실행되기 때문에 여러번의 인증을 막을 수 있음  

![image](https://user-images.githubusercontent.com/67637716/232114096-15cd0fe2-51e1-45e5-8467-004d51244294.png)  







