package com.example.jointest.util;

import io.jsonwebtoken.Claims;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


// token 생성, token 정보 추출, token 유효성 검
@Service
public class JwtUtil {

    // secretKey 설정
    private String secretKey = "javatechie";

    // 토큰 유효시간 30분
    private Long tokenValidTime = 30 * 60 * 1000L;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 토큰에서 회원 정보 추출
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    // JWT 생성 
    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims).setSubject(subject) // 정보 저장
                .setIssuedAt(new Date(System.currentTimeMillis())) // 토큰 발행 시간 저장
                .setExpiration(new Date(System.currentTimeMillis() + tokenValidTime))
                // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey).compact();
                // 사용할 암호화 알고리즘과
                // signature에 들어갈 secret 값을 세팅
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
