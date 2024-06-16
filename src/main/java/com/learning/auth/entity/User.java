package com.learning.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.minidev.json.annotate.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

@Table(name = "users")
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder

public class User implements UserDetails, OAuth2User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, nullable = false)
    private String username;
    private String password;
    @Column(unique = true)
    private String email;
    private String firstName;
    private String lastName;

    //    email verification
    private boolean verified;
//    // this user have already registered but not verified, so other user can register with this email
//    private boolean draft;


    private String picture;

    //    enable 2fa
    private boolean mfaEnabled;
    private String secret;

    @JsonIgnore
    private boolean enabled;




//    oauth2

    @NotNull
    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider;

    @Column(name = "provider_id")

    private String providerId;



    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();


    @OneToMany(mappedBy = "user")
    private List<Token> tokens = new ArrayList<>();


    @Override
    public String getUsername() {
        return email;
    }


    @Override
    public Map<String, Object> getAttributes() {
        return Map.of("id", id, "username", username, "email", email, "firstName", firstName, "lastName", lastName, "verified", verified);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName().name()));
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }


    @PrePersist
    public void prePersist() {
        enabled = true;
        verified = false;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }
}
