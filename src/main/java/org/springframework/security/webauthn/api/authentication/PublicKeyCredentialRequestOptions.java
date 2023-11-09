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

package org.springframework.security.webauthn.api.authentication;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.AuthenticationExtensionsClientInputs;
import org.springframework.security.webauthn.api.registration.DefaultAuthenticationExtensionsClientInputs;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialDescriptor;
import org.springframework.security.webauthn.api.registration.UserVerificationRequirement;
import org.springframework.security.webauthn.jackson.DurationSerializer;

import java.time.Duration;
import java.util.List;

@JsonInclude(content = JsonInclude.Include.NON_NULL)
public class PublicKeyCredentialRequestOptions {
	private final BufferSource challenge;

	@JsonSerialize(using = DurationSerializer.class)
	private final Duration timeout;

	private final String rpId;

	private final List<PublicKeyCredentialDescriptor> allowCredentials;

	private final UserVerificationRequirement userVerification;

	private final AuthenticationExtensionsClientInputs extensions;

	public PublicKeyCredentialRequestOptions(BufferSource challenge, Duration timeout, String rpId, List<PublicKeyCredentialDescriptor> allowCredentials, UserVerificationRequirement userVerification, AuthenticationExtensionsClientInputs extensions) {
		this.challenge = challenge;
		this.timeout = timeout;
		this.rpId = rpId;
		this.allowCredentials = allowCredentials;
		this.userVerification = userVerification;
		this.extensions = extensions;
	}

	public BufferSource getChallenge() {
		return this.challenge;
	}

	public Duration getTimeout() {
		return this.timeout;
	}

	public String getRpId() {
		return this.rpId;
	}

	public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
		return this.allowCredentials;
	}

	public UserVerificationRequirement getUserVerification() {
		return this.userVerification;
	}

	public AuthenticationExtensionsClientInputs getExtensions() {
		return this.extensions;
	}

	public static PublicKeyCredentialRequestOptionsBuilder builder() {
		return new PublicKeyCredentialRequestOptionsBuilder();
	}

	public static final class PublicKeyCredentialRequestOptionsBuilder {
		private BufferSource challenge;
		private Duration timeout;
		private String rpId;
		private List<PublicKeyCredentialDescriptor> allowCredentials;
		private UserVerificationRequirement userVerification;
		private AuthenticationExtensionsClientInputs extensions = new DefaultAuthenticationExtensionsClientInputs();

		private PublicKeyCredentialRequestOptionsBuilder() {
		}

		public static PublicKeyCredentialRequestOptionsBuilder aPublicKeyCredentialRequestOptions() {
			return new PublicKeyCredentialRequestOptionsBuilder();
		}

		public PublicKeyCredentialRequestOptionsBuilder challenge(BufferSource challenge) {
			this.challenge = challenge;
			return this;
		}

		public PublicKeyCredentialRequestOptionsBuilder timeout(Duration timeout) {
			this.timeout = timeout;
			return this;
		}

		public PublicKeyCredentialRequestOptionsBuilder rpId(String rpId) {
			this.rpId = rpId;
			return this;
		}

		public PublicKeyCredentialRequestOptionsBuilder allowCredentials(List<PublicKeyCredentialDescriptor> allowCredentials) {
			this.allowCredentials = allowCredentials;
			return this;
		}

		public PublicKeyCredentialRequestOptionsBuilder userVerification(UserVerificationRequirement userVerification) {
			this.userVerification = userVerification;
			return this;
		}

		public PublicKeyCredentialRequestOptionsBuilder extensions(AuthenticationExtensionsClientInputs extensions) {
			this.extensions = extensions;
			return this;
		}

		public PublicKeyCredentialRequestOptions build() {
			return new PublicKeyCredentialRequestOptions(this.challenge, this.timeout, this.rpId,
					this.allowCredentials, this.userVerification, this.extensions);
		}
	}
}
