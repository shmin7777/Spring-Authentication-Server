package com.example.auth.domain.dto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SignupDto {
    private String email;
    private String password;

    @Builder
    public SignupDto(String email, String password) {
        this.email = email;
        this.password = password;
    }

    
    public static SignupDto encodePassword(SignupDto signupDto, String encodingPassword) {
        return SignupDto.builder()
                .email(signupDto.getEmail())
                .password(encodingPassword)
                .build();
    }
}
