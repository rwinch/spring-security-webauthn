/*
 * Copyright 2002-2023 the original author or authors.
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

import com.yubico.internal.util.JacksonCodecs;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.webauthn.management.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private final WebAuthnRelyingPartyOperations rpOptions;
	private final UserCredentialRepository userCredentials;
	private final HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(Jackson2ObjectMapperBuilder.json().modules(new WebauthnJackson2Module()).build());
	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private RequestMatcher matcher = antMatcher(HttpMethod.POST, "/webauthn/register");

	private RequestMatcher removeCredentialMatcher = antMatcher(HttpMethod.POST, "/webauthn/register/{id}");

	public WebAuthnRegistrationFilter(UserCredentialRepository userCredentials, WebAuthnRelyingPartyOperations rpOptions) {
		this.userCredentials = userCredentials;
		this.rpOptions = rpOptions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (this.matcher.matches(request)) {
			registerCredential(request, response);
			return;
		}
		RequestMatcher.MatchResult matcher = this.removeCredentialMatcher.matcher(request);
		if (matcher.isMatch()) {
			String id = matcher.getVariables().get("id");
			removeCredential(request, response, id);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void registerCredential(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
		// FIXME: Read RegistrationRequest(PublicKeyCredential,String label)
		RelyingPartyRequest relyingPartyRequest = (RelyingPartyRequest) this.converter.read(RelyingPartyRequest.class, inputMessage);
		PublicKeyCredentialCreationOptions options = this.creationOptionsRepository.load(request);
		this.rpOptions.registerCredential(new RelyingPartyRegistrationRequest(options, relyingPartyRequest.getPublicKey()));
		response.getWriter().write("{ \"verified\": \"true\" }");
	}

	private void removeCredential(HttpServletRequest request, HttpServletResponse response, String id) throws IOException {
		this.userCredentials.delete(ArrayBuffer.fromBase64(id));
		response.sendRedirect("/webauthn/register?success");
	}

	// FIXME: make private
	public static class RelyingPartyRequest {
		private RelyingPartyPublicKey publicKey;

		public RelyingPartyPublicKey getPublicKey() {
			return this.publicKey;
		}

		public void setPublicKey(RelyingPartyPublicKey publicKey) {
			this.publicKey = publicKey;
		}
	}
}
