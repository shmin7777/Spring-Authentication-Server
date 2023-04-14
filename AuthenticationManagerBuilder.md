``` java
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public void login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());
        AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject();
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
    }
}

```    

여기서 `AuthenticationManagerBuilder`는 언제 생성되는 것인가 궁금하여 stack trace를 따라가 보았다.  

![image](https://user-images.githubusercontent.com/67637716/231920434-bb95fda8-b20f-4cef-9ae6-4e9cf5366d67.png)  

`AuthenticationConfiguration` 라는 spring security class에 @Configuration이 붙어져 있고, `AuthenticationManagerBuilder`가 @Bean으로 붙어져 있음을 확인.  



