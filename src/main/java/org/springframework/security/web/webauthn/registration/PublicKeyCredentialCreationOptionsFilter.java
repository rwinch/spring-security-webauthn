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

package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A {@link jakarta.servlet.Filter} that can be used to provide the
 */
public class PublicKeyCredentialCreationOptionsFilter extends OncePerRequestFilter {

	private PublicKeyCredentialCreationOptionsRepository repository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private RequestMatcher matcher = AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/webauthn/register/options");

	private final WebAuthnRelyingPartyOperations rpOperations;

	private final HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(Jackson2ObjectMapperBuilder.json().modules(new WebauthnJackson2Module()).build());

	public PublicKeyCredentialCreationOptionsFilter(WebAuthnRelyingPartyOperations rpOperations) {
		this.rpOperations = rpOperations;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		SecurityContext context = SecurityContextHolder.getContext();
		PublicKeyCredentialCreationOptions options = this.rpOperations.createPublicKeyCredentialCreationOptions(context.getAuthentication());
		this.repository.save(request, response, options);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.converter.write(options, MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
	}
}
