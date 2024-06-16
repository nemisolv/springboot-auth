package com.learning.auth.exception;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class Error {
    private String path;
    private LocalDateTime time;
    private List<String> errors;
    private int code;

    public void addError(String error) {
        errors.add(error);
    }
}
