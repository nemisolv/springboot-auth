package com.learning.auth.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${app.secure.jwt.secret-key}")
    private String secretKey;
    @Value("${app.secure.jwt.token-expire}")
    private long tokenExpire;
    @Value("${app.secure.jwt.refreshToken-expire}")
    private long refreshTokenExpire;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractTokenExpire(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken( UserDetails userDetails) {
        return buildToken(new HashMap<>(),userDetails, tokenExpire);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(),userDetails, refreshTokenExpire);
    }


    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims,userDetails, tokenExpire);
    }

    public String generateRefreshToken(Map<String,Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims,userDetails, refreshTokenExpire);
    }

    public String generateTokenWithExpire(UserDetails userDetails, long expire) {
        return buildToken(new HashMap<>(),userDetails, expire);
    }




    private String buildToken(Map<String,Object> extraClaims, UserDetails userDetails, long expire) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expire) )
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }






    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver)
    {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isValidToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && extractTokenExpire(token).after(new Date());
    }

    private Key getSignInKey() {
        byte [] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);

    }

}
