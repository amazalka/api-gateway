package com.example.apigateway;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
public class DebugController {
    @GetMapping("/me")
    public Collection<? extends GrantedAuthority> me(Authentication authentication) {
        return authentication.getAuthorities();
    }
}
