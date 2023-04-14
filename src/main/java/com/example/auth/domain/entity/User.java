package com.example.auth.domain.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import com.example.auth.domain.dto.SignupDto;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;
    private String email; // principal
    private String password; // credential
    @Enumerated(EnumType.STRING) // 변수명 그대로 저장
    private Role role;

    // == 생성 메서드 == //
    public static User registerUser(SignupDto signupDto) {
        User user = new User();
        user.email = signupDto.getEmail();
        user.password = signupDto.getPassword();
        user.role = Role.USER;
        return user;
    }
}
