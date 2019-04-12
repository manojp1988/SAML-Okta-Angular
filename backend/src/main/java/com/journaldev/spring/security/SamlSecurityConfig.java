package com.journaldev.spring.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLRelayStateSuccessHandler;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.journaldev.spring.service.SamlUserDetailsServiceImpl;

/**
 * @author slemoine
 */
@Configuration
@EnableWebSecurity
public class SamlSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${security.saml2.metadata-url}")
	String metadataFilePath;

	@Bean
	public WebSSOProfileOptions defaultWebSSOProfileOptions() {
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setIncludeScoping(false);
		return webSSOProfileOptions;
	}

	@Bean
	public SAMLEntryPoint samlEntryPoint() {
		SAMLEntryPoint samlEntryPoint = new SamlWithRelayStateEntryPoint();
		samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
		return samlEntryPoint;
	}

	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() {
		return new MetadataDisplayFilter();
	}

	@Bean
	public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
		return new SimpleUrlAuthenticationFailureHandler();
	}

	@Bean
	public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
		SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SAMLRelayStateSuccessHandler();
		return successRedirectHandler;
	}

	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOProcessingFilter;
	}

	@Bean
	public HttpStatusReturningLogoutSuccessHandler successLogoutHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}

	@Bean
	public SecurityContextLogoutHandler logoutHandler() {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		return logoutHandler;
	}

	@Bean
	public SAMLLogoutFilter samlLogoutFilter() {
		return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() },
				new LogoutHandler[] { logoutHandler() });
	}

	@Bean
	public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
		return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	}

	@Bean
	public MetadataGeneratorFilter metadataGeneratorFilter() {
		return new MetadataGeneratorFilter(metadataGenerator());
	}

	@Bean
	public MetadataGenerator metadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		metadataGenerator.setEntityId("DemoApp");
		metadataGenerator.setEntityBaseURL("https://dev.spectrags.com/backend");
		metadataGenerator.setExtendedMetadata(extendedMetadata());
		metadataGenerator.setIncludeDiscoveryExtension(false);
		metadataGenerator.setKeyManager(keyManager());
		return metadataGenerator;
	}

	@Bean
	public KeyManager keyManager() {
		ClassPathResource storeFile = new ClassPathResource("/saml/app.keystore");
		String storePass = "BDSfweiu@21";
		Map<String, String> passwords = new HashMap<>();
		passwords.put("server", "BDSfweiu@21");
		return new JKSKeyManager(storeFile, storePass, passwords, "server");
	}

	@Bean
	public ExtendedMetadata extendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(false);
		extendedMetadata.setSignMetadata(false);
		return extendedMetadata;
	}

	@Bean
	public FilterChainProxy samlFilter() throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<>();

		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
				metadataDisplayFilter()));

		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));

		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
				samlWebSSOProcessingFilter()));

		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));

		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
				samlLogoutProcessingFilter()));

		return new FilterChainProxy(chains);
	}

	@Bean
	public VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	@Bean(initMethod = "initialize")
	public StaticBasicParserPool parserPool() {
		return new StaticBasicParserPool();
	}

	@Bean(name = "parserPoolHolder")
	public ParserPoolHolder parserPoolHolder() {
		return new ParserPoolHolder();
	}

	@Bean
	public HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(parserPool(), velocityEngine());
	}

	@Bean
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(parserPool());
	}

	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		return new SAMLProcessorImpl(bindings);
	}

	@Bean
	public HttpClient httpClient() {
		return new HttpClient(multiThreadedHttpConnectionManager());
	}

	@Bean
	public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
		return new MultiThreadedHttpConnectionManager();
	}

	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new SAMLBootstrap();
	}

	@Bean
	public SAMLDefaultLogger samlLogger() {
		return new SAMLDefaultLogger();
	}

	@Bean
	public SAMLContextProviderImpl contextProvider() {
		return new SAMLContextProviderImpl();
	}

	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		return new WebSSOProfileConsumerImpl();
	}

	@Bean
	public WebSSOProfile webSSOprofile() {
		return new WebSSOProfileImpl();
	}

	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	@Bean
	public SingleLogoutProfile logoutprofile() {
		return new SingleLogoutProfileImpl();
	}

	@Bean
	public ExtendedMetadataDelegate idpMetadata() throws MetadataProviderException, ResourceException {
		Timer backgroundTaskTimer = new Timer(true);

		HTTPMetadataProvider resourceBackedMetadataProvider = new HTTPMetadataProvider(backgroundTaskTimer,
				new HttpClient(), metadataFilePath);

		resourceBackedMetadataProvider.setParserPool(parserPool());

		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceBackedMetadataProvider,
				extendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(false);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}

	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException {
		List<MetadataProvider> providers = new ArrayList<>();
		providers.add(idpMetadata());

		CachingMetadataManager cachingMetadataManager = null;
		try {
			cachingMetadataManager = new CachingMetadataManager(providers);
		} catch (MetadataProviderException e) {
			e.printStackTrace();
		}

		cachingMetadataManager.setKeyManager(keyManager());
		return cachingMetadataManager;
	}

	@Bean
	public SAMLUserDetailsService samlUserDetailsService() {
		return new SamlUserDetailsServiceImpl();
	}

	@Bean
	public SAMLAuthenticationProvider samlAuthenticationProvider() {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setUserDetails(samlUserDetailsService());
		samlAuthenticationProvider.setForcePrincipalAsString(false);
		return samlAuthenticationProvider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(samlAuthenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// @formatter:off
		http
				.exceptionHandling()
					.authenticationEntryPoint(samlEntryPoint())
				.and()
					.csrf().disable()
					.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
					.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
					.authorizeRequests()
						.antMatchers("/index.html").permitAll()
						.antMatchers("/health").permitAll()
						.antMatchers("/error").permitAll()
						.antMatchers("/saml/**").permitAll()
						.anyRequest().authenticated()
				.and()
					.logout().logoutSuccessUrl("/");
		// @formatter:on

	}

}
