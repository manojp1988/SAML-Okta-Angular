package com.journaldev.spring.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

	
	@Value("${security.saml2.metadata-url}")
	String metadataFilePath;
	
	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/health")
	public String ok() {
		return "All OK!";
	}
}
