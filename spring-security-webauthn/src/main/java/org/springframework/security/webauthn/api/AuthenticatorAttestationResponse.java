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
 * @since 6.4
 * @author Rob Winch
 */
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {

	private final Bytes attestationObject;

	private final List<AuthenticatorTransport> transports;

	/**
	 * FIXME: This is computed from the attestationObject. Needs to be an interface so that can be computed or injected
	 */
	private final Bytes authenticatorData;

	private final Bytes publicKey;

	private final COSEAlgorithmIdentifier publicKeyAlgorithm;

	private AuthenticatorAttestationResponse(Bytes clientDataJSON, Bytes attestationObject, List<AuthenticatorTransport> transports, Bytes authenticatorData, Bytes publicKey, COSEAlgorithmIdentifier publicKeyAlgorithm) {
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
	public Bytes getAttestationObject() {
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
	public Bytes getAuthenticatorData() {
		return this.authenticatorData;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getpublickey">publicKey</a>
	 * returns the DER <a href="https://tools.ietf.org/html/rfc5280#section-4.1.2.7">SubjectPublicKeyInfo</a> of the new
	 * credential, or null if this is not available.
	 * @return the publicKey
	 */
	public Bytes getPublicKey() {
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

	/**
	 * Builds {@link AuthenticatorAssertionResponse}.
	 *
	 * @since 6.4
	 * @author Rob Winch
	 */
	public static final class AuthenticatorAttestationResponseBuilder {
		private Bytes attestationObject;
		private List<AuthenticatorTransport> transports;
		private Bytes authenticatorData;
		private Bytes publicKey;
		private COSEAlgorithmIdentifier publicKeyAlgorithm;
		private Bytes clientDataJSON;

		private AuthenticatorAttestationResponseBuilder() {
		}

		/**
		 * Sets the {@link #getAttestationObject()} property.
		 *
		 * @param attestationObject the attestation object.
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder attestationObject(Bytes attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		/**
		 * Sets the {@link #getTransports()} property.
		 *
		 * @param transports the transports
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder transports(AuthenticatorTransport... transports) {
			return transports(Arrays.asList(transports));
		}

		/**
		 * Sets the {@link #getTransports()} property.
		 *
		 * @param transports the transports
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder transports(List<AuthenticatorTransport> transports) {
			this.transports = transports;
			return this;
		}

		/**
		 * Sets the {@link #getAuthenticatorData()} property.
		 *
		 * @param authenticatorData the authenticator data.
		 * @return  the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder authenticatorData(Bytes authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		/**
		 * Sets the {@link #getPublicKey()} property.
		 *
		 * @param publicKey the public key.
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder publicKey(Bytes publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		/**
		 * Sets the {@link #getPublicKeyAlgorithm()} property.
		 * @param publicKeyAlgorithm the public key algorithm
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder publicKeyAlgorithm(COSEAlgorithmIdentifier publicKeyAlgorithm) {
			this.publicKeyAlgorithm = publicKeyAlgorithm;
			return this;
		}

		/**
		 * Sets the {@link #getClientDataJSON()} property.
		 * @param clientDataJSON the client data JSON.
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponseBuilder clientDataJSON(Bytes clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		/**
		 * Builds a {@link AuthenticatorAssertionResponse}.
		 *
		 * @return the {@link AuthenticatorAttestationResponseBuilder}
		 */
		public AuthenticatorAttestationResponse build() {
			return new AuthenticatorAttestationResponse(this.clientDataJSON, this.attestationObject, this.transports, this.authenticatorData, this.publicKey, this.publicKeyAlgorithm);
		}

	}

}
