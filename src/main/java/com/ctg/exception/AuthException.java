package com.ctg.exception;

public class AuthException extends RuntimeException {
    public AuthException(String msg) {
        super(msg);
    }
}