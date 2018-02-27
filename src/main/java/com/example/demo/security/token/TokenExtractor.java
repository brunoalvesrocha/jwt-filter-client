package com.example.demo.security.token;

/**
 * @author brunorocha
 */

public interface TokenExtractor {
    String extract(String payload);
}