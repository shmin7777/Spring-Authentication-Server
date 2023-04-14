package com.example.auth.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.auth.domain.dto.LoginDto;
import com.example.auth.domain.dto.SignupDto;
import com.example.auth.domain.dto.TokenDto;
import com.example.auth.domain.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.jwt.JwtProvider;
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

    @Transactional
    public void registerUser(SignupDto signupDto) {
        String encodePassword = passwordEncoder.encode(signupDto.getPassword());
        User user = User.registerUser(SignupDto.encodePassword(signupDto, encodePassword));
        userRepository.save(user);
    }

    public TokenDto login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(),
                        loginDto.getPassword());
        AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject();
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return jwtProvider.generateToken(authentication);


    }
}
