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

package org.springframework.security.webauthn.api;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.Arrays;
import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse
 */
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
	private final Base64Url attestationObject;

	private final List<AuthenticatorTransport> transports;

	/**
	 * FIXME: This is computed from the attestationObject. Needs to be an interface so that can be computed or injected
	 */
	private final Base64Url authenticatorData;

	private final Base64Url publicKey;

	private final COSEAlgorithmIdentifier publicKeyAlgorithm;

	public AuthenticatorAttestationResponse(Base64Url clientDataJSON, Base64Url attestationObject, List<AuthenticatorTransport> transports, Base64Url authenticatorData, Base64Url publicKey, COSEAlgorithmIdentifier publicKeyAlgorithm) {
		super(clientDataJSON);
		this.attestationObject = attestationObject;
		this.transports = transports;
		this.authenticatorData = authenticatorData;
		this.publicKey = publicKey;
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	public Base64Url getAttestationObject() {
		return this.attestationObject;
	}

	public List<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	public Base64Url getAuthenticatorData() {
		return this.authenticatorData;
	}

	public Base64Url getPublicKey() {
		return this.publicKey;
	}

	public COSEAlgorithmIdentifier getPublicKeyAlgorithm() {
		return this.publicKeyAlgorithm;
	}

	public static AuthenticatorAttestationResponseBuilder builder() {
		return new AuthenticatorAttestationResponseBuilder();
	}

	@JsonPOJOBuilder(withPrefix = "") // FIXME: Remove JsonPOJOBuilder
	public static final class AuthenticatorAttestationResponseBuilder {
		private Base64Url attestationObject;
		private List<AuthenticatorTransport> transports;
		private Base64Url authenticatorData;
		private Base64Url publicKey;
		private COSEAlgorithmIdentifier publicKeyAlgorithm;
		private Base64Url clientDataJSON;

		private AuthenticatorAttestationResponseBuilder() {
		}

		public static AuthenticatorAttestationResponseBuilder anAuthenticatorAttestationResponse() {
			return new AuthenticatorAttestationResponseBuilder();
		}

		public AuthenticatorAttestationResponseBuilder attestationObject(Base64Url attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder transports(AuthenticatorTransport... transports) {
			return transports(Arrays.asList(transports));
		}

		@JsonSetter // FIXME: externalize
		public AuthenticatorAttestationResponseBuilder transports(List<AuthenticatorTransport> transports) {
			this.transports = transports;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder authenticatorData(Base64Url authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder publicKey(Base64Url publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder publicKeyAlgorithm(COSEAlgorithmIdentifier publicKeyAlgorithm) {
			this.publicKeyAlgorithm = publicKeyAlgorithm;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder clientDataJSON(Base64Url clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		public AuthenticatorAttestationResponse build() {
			return new AuthenticatorAttestationResponse(clientDataJSON, attestationObject, transports, authenticatorData, publicKey, publicKeyAlgorithm);
		}
	}
}
