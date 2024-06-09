package com.learning.auth.entity;

public enum RoleName {
    USER("user"), MANAGER("manager"), ADMIN("admin"), SUPER_ADMIN("super_admin");

    private final String value;

    RoleName(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static RoleName fromValue(String value) {
        for (RoleName roleName : RoleName.values()) {
            if (roleName.getValue().equals(value)) {
                return roleName;
            }
        }
        return null;
    }
}
