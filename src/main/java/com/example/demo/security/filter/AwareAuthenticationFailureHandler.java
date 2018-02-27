package com.example.demo.security.filter;

import com.example.demo.security.common.ErrorCode;
import com.example.demo.security.common.ErrorResponse;
import com.example.demo.security.exception.AuthMethodNotSupportedException;
import com.example.demo.security.exception.JwtExpiredTokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author brunorocha
 */
@Component
public class AwareAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper mapper;

    @Autowired
    public AwareAuthenticationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (e instanceof BadCredentialsException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                    "Invalid username or password", ErrorCode.AUTHENTICATION));
        } else if (e instanceof JwtExpiredTokenException) {
            mapper.writeValue(response.getWriter(), ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                    "Token has expired", ErrorCode.JWT_TOKEN_EXPIRED));
        } else if (e instanceof AuthMethodNotSupportedException) {
            mapper.writeValue(response.getWriter(),
                    ErrorResponse.of(HttpStatus.UNAUTHORIZED, e.getMessage(), ErrorCode.AUTHENTICATION));
        }

        mapper.writeValue(response.getWriter(), ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                "Authentication failed", ErrorCode.AUTHENTICATION));
    }
}