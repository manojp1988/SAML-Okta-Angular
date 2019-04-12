package com.journaldev.spring.security.jwt;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import com.journaldev.spring.security.SecurityConstant;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

/**
 * @author slemoine
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        Assert.notNull(authentication, "Authentication is missing");

        Assert.isInstanceOf(JwtAuthenticationToken.class, authentication,
                "This method only accepts JwtAuthenticationToken");

        String jwtToken = authentication.getName();

        if (authentication.getPrincipal() == null || jwtToken == null) {
            throw new AuthenticationCredentialsNotFoundException("Authentication token is missing");
        }


        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtToken);

            boolean isVerified = signedJWT.verify(new MACVerifier(SecurityConstant.JWT_SECRET.getBytes()));

            if(!isVerified){
                throw new BadCredentialsException("Invalid token signature");
            }

            //is token expired ?
            LocalDateTime expirationTime = LocalDateTime.ofInstant(
                    signedJWT.getJWTClaimsSet().getExpirationTime().toInstant(), ZoneId.systemDefault());

            if (LocalDateTime.now(ZoneId.systemDefault()).isAfter(expirationTime)) {
                throw new CredentialsExpiredException("Token expired");
            }

            return new JwtAuthenticationToken(signedJWT, null, null);

        } catch (ParseException e) {
            throw new InternalAuthenticationServiceException("Unreadable token");
        } catch (JOSEException e) {
            throw new InternalAuthenticationServiceException("Unreadable signature");
        }
    }
}