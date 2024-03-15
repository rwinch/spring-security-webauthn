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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.springframework.security.webauthn.api.ArrayBuffer;

import java.util.Arrays;
import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse
 */
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
	private final ArrayBuffer attestationObject;

	private final List<AuthenticatorTransport> transports;

	/**
	 * FIXME: This is computed from the attestationObject. Needs to be an interface so that can be computed or injected
	 */
	private final ArrayBuffer authenticatorData;

	private final ArrayBuffer publicKey;

	private final COSEAlgorithmIdentifier publicKeyAlgorithm;

	public AuthenticatorAttestationResponse(ArrayBuffer clientDataJSON, ArrayBuffer attestationObject, List<AuthenticatorTransport> transports, ArrayBuffer authenticatorData, ArrayBuffer publicKey, COSEAlgorithmIdentifier publicKeyAlgorithm) {
		super(clientDataJSON);
		this.attestationObject = attestationObject;
		this.transports = transports;
		this.authenticatorData = authenticatorData;
		this.publicKey = publicKey;
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	public ArrayBuffer getAttestationObject() {
		return this.attestationObject;
	}

	public List<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	public ArrayBuffer getAuthenticatorData() {
		return this.authenticatorData;
	}

	public ArrayBuffer getPublicKey() {
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
		private ArrayBuffer attestationObject;
		private List<AuthenticatorTransport> transports;
		private ArrayBuffer authenticatorData;
		private ArrayBuffer publicKey;
		private COSEAlgorithmIdentifier publicKeyAlgorithm;
		private ArrayBuffer clientDataJSON;

		private AuthenticatorAttestationResponseBuilder() {
		}

		public static AuthenticatorAttestationResponseBuilder anAuthenticatorAttestationResponse() {
			return new AuthenticatorAttestationResponseBuilder();
		}

		public AuthenticatorAttestationResponseBuilder attestationObject(ArrayBuffer attestationObject) {
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

		public AuthenticatorAttestationResponseBuilder authenticatorData(ArrayBuffer authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder publicKey(ArrayBuffer publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder publicKeyAlgorithm(COSEAlgorithmIdentifier publicKeyAlgorithm) {
			this.publicKeyAlgorithm = publicKeyAlgorithm;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder clientDataJSON(ArrayBuffer clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		public AuthenticatorAttestationResponse build() {
			return new AuthenticatorAttestationResponse(clientDataJSON, attestationObject, transports, authenticatorData, publicKey, publicKeyAlgorithm);
		}
	}
}
