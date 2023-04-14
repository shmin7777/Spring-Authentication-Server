package com.example.auth.service;

import java.time.Duration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class RedisService {
    private final StringRedisTemplate stringRedisTemplate;

    public String getValues(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }

    @Transactional
    public void setValues(String key, String value) {
        stringRedisTemplate.opsForValue().set(key, value);
    }

    @Transactional
    public void setValuesWithTimeout(String key, String value, long timeout) {
        stringRedisTemplate.opsForValue().set(key, value, Duration.ofMillis(timeout));
    }

    @Transactional
    public boolean deleteValue(String key) {
        return stringRedisTemplate.delete(key);
    }

}
