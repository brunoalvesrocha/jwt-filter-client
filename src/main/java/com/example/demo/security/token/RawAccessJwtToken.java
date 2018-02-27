package com.example.demo.security.token;

import com.example.demo.security.exception.JwtExpiredTokenException;
import com.example.demo.security.jwt.JwtToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * @author brunorocha
 */
public class RawAccessJwtToken implements JwtToken {

    private static Logger logger = LoggerFactory.getLogger(RawAccessJwtToken.class);

    private String token;

    public RawAccessJwtToken(String token) {
        this.token = token;
    }

    public Jws<Claims> parseClaims(String siginKey) {
        try {
            return Jwts.parser().setSigningKey(siginKey).parseClaimsJws(this.token);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            logger.error("Invalid JWT Token", ex);
            throw new BadCredentialsException("Invalid JWT token", ex);
        } catch (ExpiredJwtException ex) {
            logger.info("JWT Token is expired", ex);
            throw new JwtExpiredTokenException(this, "JWT Token expired", ex);
        }
    }

    @Override
    public String getToken() {
        return token;
    }
}