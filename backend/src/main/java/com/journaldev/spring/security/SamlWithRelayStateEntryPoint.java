package com.journaldev.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class SamlWithRelayStateEntryPoint extends SAMLEntryPoint {

	/**
	 * Metadata manager, cannot be null, must be set. It is set directly in the
	 * custom config, so can be optional here. User could override it if desired.
	 *
	 * @param metadata manager
	 */
	@Autowired(required = false)
	@Override
	public void setMetadata(MetadataManager metadata) {
		super.setMetadata(metadata);
	}

	/**
	 * Logger for SAML events, cannot be null, must be set.
	 *
	 * @param samlLogger logger It is set in the custom config, so can be optional
	 *                   here. User could override it if desired.
	 */
	@Autowired(required = false)
	@Override
	public void setSamlLogger(SAMLLogger samlLogger) {
		super.setSamlLogger(samlLogger);
	}

	/**
	 * Profile for consumption of processed messages, cannot be null, must be set.
	 * It is set in the custom config, so can be optional here. User could override
	 * it if desired.
	 *
	 * @param webSSOprofile profile
	 */
	@Autowired(required = false)
	@Qualifier("webSSOprofile")
	@Override
	public void setWebSSOprofile(WebSSOProfile webSSOprofile) {
		super.setWebSSOprofile(webSSOprofile);
	}

	/**
	 * Sets entity responsible for populating local entity context data. It is set
	 * in the custom config, so can be optional here. User could override it if
	 * desired.
	 *
	 * @param contextProvider provider implementation
	 */
	@Autowired(required = false)
	@Override
	public void setContextProvider(SAMLContextProvider contextProvider) {
		super.setContextProvider(contextProvider);
	}

	@Override
	protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) {

		WebSSOProfileOptions ssoProfileOptions;
		if (defaultOptions != null) {
			ssoProfileOptions = defaultOptions.clone();
		} else {
			ssoProfileOptions = new WebSSOProfileOptions();
		}

		// Not :
		// Add your custom logic here if you need it.
		// Original HttpRequest can be extracted from the context param
		// So you can let the caller pass you some special param which can be used to
		// build an on-the-fly custom
		// relay state param

		ssoProfileOptions.setRelayState("https://dev.spectrags.com/html/home");

		return ssoProfileOptions;
	}

}
