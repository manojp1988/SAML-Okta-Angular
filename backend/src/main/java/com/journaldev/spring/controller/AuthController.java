package com.journaldev.spring.controller;

import java.util.ArrayList;

import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.journaldev.spring.dto.ApiToken;
import com.journaldev.spring.dto.Credentials;
import com.journaldev.spring.security.SecurityConstant;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * @author slemoine
 */
@RestController
@RequestMapping(value = "/auth", produces = "application/json")
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@GetMapping("/token")
	public ApiToken token() throws JOSEException {

		final DateTime dateTime = DateTime.now();

		// build claims
		JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
		jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(120).toDate());
		jwtClaimsSetBuilder.claim("APP", "SAMPLE");

		// signature
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
		signedJWT.sign(new MACSigner(SecurityConstant.JWT_SECRET));

		return new ApiToken(signedJWT.serialize());
	}
	
	@PostMapping("/formLogin")
	public ApiToken formToken(@RequestBody Credentials creds) throws KeyLengthException, JOSEException {
		
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(), new ArrayList<>()));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		final DateTime dateTime = DateTime.now();

		// build claims
		JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
		jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(120).toDate());
		jwtClaimsSetBuilder.claim("APP", "SAMPLE");

		// signature
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
		signedJWT.sign(new MACSigner(SecurityConstant.JWT_SECRET));

		return new ApiToken(signedJWT.serialize());
	}
}
