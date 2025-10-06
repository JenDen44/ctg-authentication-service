package com.ctg.domain;

import lombok.Data;

@Data
public class UserRecord {
    private Long id;
    private String fullName;
    private String email;
    private String passwordHash;
    private Role role;
    private Integer tokenVersion;
}
