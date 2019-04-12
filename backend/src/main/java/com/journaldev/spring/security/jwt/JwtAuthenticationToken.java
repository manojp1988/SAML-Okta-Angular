package com.journaldev.spring.security.jwt;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author slemoine
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final transient Object principal;

    public JwtAuthenticationToken(Object principal) {
        super(null);
        this.principal=principal;
    }

    public JwtAuthenticationToken(Object principal, Object details, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setDetails(details);
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
