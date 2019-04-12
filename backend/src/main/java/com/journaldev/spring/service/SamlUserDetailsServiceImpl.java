package com.journaldev.spring.service;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import com.journaldev.spring.model.SamlUserDetails;


/**
 * @author slemoine
 */
public class SamlUserDetailsServiceImpl implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        return new SamlUserDetails();
    }
}