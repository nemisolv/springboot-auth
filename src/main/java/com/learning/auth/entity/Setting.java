package com.learning.auth.entity;

import jakarta.persistence.*;
import lombok.*;

@Table(name = "settings")
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Setting extends BaseEntity {

    @Column(unique = true, nullable = false, name = "`key`")
    @EqualsAndHashCode.Include
    private String key;

    @Column(columnDefinition = "TEXT")
    private String value;

    @Enumerated(EnumType.STRING)
    private SettingCategory category;

    public Setting(String key) {
        this.key = key;
    }
}
