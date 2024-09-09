/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultWebauthnLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.registration.DefaultWebAuthnRegistrationPageGeneratingFilter;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.authentication.WebAuthnAuthenticationProvider;
import org.springframework.security.webauthn.management.*;
import org.springframework.util.ClassUtils;

import java.util.*;

/**
 * Configures WebAuthn for Spring Security applications
 * @since 6.4
 * @author Rob Winch
 * @param <B> the type of builder
 */
public class WebauthnConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<WebauthnConfigurer<B>, B> {

	private String rpId;

	private String rpName;

	private Set<String> allowedOrigins = new HashSet<>();


	public WebauthnConfigurer<B> rpId(String rpId) {
		this.rpId = rpId;
		return this;
	}

	public WebauthnConfigurer<B> rpName(String rpName) {
		this.rpName = rpName;
		return this;
	}

	public WebauthnConfigurer<B> allowedOrigins(String... allowedOrigins) {
		this.allowedOrigins = Set.of(allowedOrigins);
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		UserDetailsService userDetailsService = getSharedOrBean(http, UserDetailsService.class).get();
		PublicKeyCredentialUserEntityRepository userEntities = getSharedOrBean(http, PublicKeyCredentialUserEntityRepository.class)
				.orElse(userEntityRepository());
		UserCredentialRepository userCredentials = getSharedOrBean(http, UserCredentialRepository.class)
				.orElse(userCredentialRepository());
		WebAuthnRelyingPartyOperations rpOperations = webAuthnRelyingPartyOperations(userEntities, userCredentials);
		WebAuthnAuthenticationFilter webAuthnAuthnFilter = new WebAuthnAuthenticationFilter();
		webAuthnAuthnFilter.setAuthenticationManager(new ProviderManager(new WebAuthnAuthenticationProvider(rpOperations, userDetailsService)));
		http.addFilterBefore(webAuthnAuthnFilter, BasicAuthenticationFilter.class);
		http.addFilterAfter(new WebAuthnRegistrationFilter(userCredentials, rpOperations), AuthorizationFilter.class);
		// FIXME: Anonymous users should not be able to register a key
		http.addFilterBefore(new PublicKeyCredentialCreationOptionsFilter(rpOperations), AuthorizationFilter.class);
		http.addFilterAfter(new DefaultWebAuthnRegistrationPageGeneratingFilter(userEntities, userCredentials), AuthorizationFilter.class);
		http.addFilterBefore(new PublicKeyCredentialRequestOptionsFilter(rpOperations), AuthorizationFilter.class);
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null) {
			UsernamePasswordAuthenticationFilter usernamePasswordFilter = http.getSharedObject(UsernamePasswordAuthenticationFilter.class);
			DefaultWebauthnLoginPageGeneratingFilter webauthnLogin = new DefaultWebauthnLoginPageGeneratingFilter(usernamePasswordFilter);
			webauthnLogin.setFormLoginEnabled(true);
			webauthnLogin.setPasskeysEnabled(true);
			webauthnLogin.setResolveHeaders((request) -> {
				CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				return Map.of( csrfToken.getHeaderName(), csrfToken.getToken());
			});
			boolean ottEnabled = isOttEnabled(http);
			if (ottEnabled) {
				webauthnLogin.setOneTimeTokenEnabled(true);
				webauthnLogin.setGenerateOneTimeTokenUrl("/ott/generate");
			}
			webauthnLogin.setLoginPageUrl("/login");
			webauthnLogin.setAuthenticationUrl("/login");
			webauthnLogin.setFailureUrl("/login?error");
			webauthnLogin.setUsernameParameter("username");
			webauthnLogin.setPasswordParameter("password");
			webauthnLogin.setResolveHiddenInputs(this::hiddenInputs);
			http.addFilterBefore(webauthnLogin, DefaultLoginPageGeneratingFilter.class);
		}
	}

	public static <B extends HttpSecurityBuilder<B>> WebauthnConfigurer<B> webauthn() {
		return new WebauthnConfigurer<>();
	}

	private boolean isOttEnabled(B http) {
		try {
			Class ottConfigurer = ClassUtils.forName("org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer", WebauthnConfigurer.class.getClassLoader());
			return http.getConfigurer(ottConfigurer) != null;
		}
		catch (Exception ex) {
			return false;
		}
	}

	private Map<String, String> hiddenInputs(HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
				: Collections.emptyMap();
	}

	private <C> Optional<C> getSharedOrBean(B http, Class<C> type) {
		C shared = http.getSharedObject(type);
		return Optional
			.ofNullable(shared)
			.or(() -> getBeanOrNull(type));
	}

	private <T> Optional<T> getBeanOrNull(Class<T> type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return Optional.empty();
		}
		try {
			return Optional.of(context.getBean(type));
		}
		catch (NoSuchBeanDefinitionException ex) {
			return Optional.empty();
		}
	}


	private MapUserCredentialRepository userCredentialRepository() {
		return new MapUserCredentialRepository();
	}

	private PublicKeyCredentialUserEntityRepository userEntityRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}

	private WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials) {
		Optional<WebAuthnRelyingPartyOperations> webauthnOperationsBean = getBeanOrNull(WebAuthnRelyingPartyOperations.class);
		if (webauthnOperationsBean.isPresent()) {
			return webauthnOperationsBean.get();
		}
		Webauthn4JRelyingPartyOperations result =  new Webauthn4JRelyingPartyOperations(userEntities, userCredentials,
				PublicKeyCredentialRpEntity.builder()
				.id(this.rpId)
				.name(this.rpName)
				.build(),
				this.allowedOrigins);
		return result;
	}
}
