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

package org.springframework.security.webauthn.api;

import java.util.Arrays;
import java.util.List;

/**
 * <a href="https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse">AuthenticatorAttestationResponse</a>
 * represents the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>'s response to a client’s
 * request for the creation of a new <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key
 * credential</a>.
 *
 * @since 6.3
 * @author Rob Winch
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

	private AuthenticatorAttestationResponse(Base64Url clientDataJSON, Base64Url attestationObject, List<AuthenticatorTransport> transports, Base64Url authenticatorData, Base64Url publicKey, COSEAlgorithmIdentifier publicKeyAlgorithm) {
		super(clientDataJSON);
		this.attestationObject = attestationObject;
		this.transports = transports;
		this.authenticatorData = authenticatorData;
		this.publicKey = publicKey;
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a>
	 * attribute contains an attestation object, which is opaque to, and cryptographically protected against tampering
	 * by, the client.
	 * @return the attestationObject
	 */
	public Base64Url getAttestationObject() {
		return this.attestationObject;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports">transports</a>
	 * returns the <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot>transports</a>
	 * @return the transports
	 */
	public List<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getauthenticatordata">authenticatorData</a>
	 * contained within attestationObject. See
	 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-public-key-easy">5.2.1.1 Easily accessing credential data</a>.
	 * @return the authenticatorData
	 */
	public Base64Url getAuthenticatorData() {
		return this.authenticatorData;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getpublickey">publicKey</a>
	 * returns the DER <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.7">SubjectPublicKeyInfo</a> of the new
	 * credential, or null if this is not available.
	 * @return the publicKey
	 */
	public Base64Url getPublicKey() {
		return this.publicKey;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getpublickeyalgorithm">publicKeyAlgorithm</a>
	 * is the {@link COSEAlgorithmIdentifier} of the new credential.
	 * @return the {@link COSEAlgorithmIdentifier}
	 */
	public COSEAlgorithmIdentifier getPublicKeyAlgorithm() {
		return this.publicKeyAlgorithm;
	}

	/**
	 * Creates a new instance.
	 * @return the {@link AuthenticatorAttestationResponseBuilder}
	 */
	public static AuthenticatorAttestationResponseBuilder builder() {
		return new AuthenticatorAttestationResponseBuilder();
	}

	public static final class AuthenticatorAttestationResponseBuilder {
		private Base64Url attestationObject;
		private List<AuthenticatorTransport> transports;
		private Base64Url authenticatorData;
		private Base64Url publicKey;
		private COSEAlgorithmIdentifier publicKeyAlgorithm;
		private Base64Url clientDataJSON;

		private AuthenticatorAttestationResponseBuilder() {
		}

		public AuthenticatorAttestationResponseBuilder attestationObject(Base64Url attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		public AuthenticatorAttestationResponseBuilder transports(AuthenticatorTransport... transports) {
			return transports(Arrays.asList(transports));
		}

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
			return new AuthenticatorAttestationResponse(this.clientDataJSON, this.attestationObject, this.transports, this.authenticatorData, this.publicKey, this.publicKeyAlgorithm);
		}
	}
}
