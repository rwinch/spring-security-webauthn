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

/**
 * The <a href="https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>
 * interface represents an <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>'s response to a
 * client’s request for generation of a new
 * <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion>authentication assertion</a> given the
 * <a href="https://www.w3.org/TR/webauthn-3/#webauthn-relying-party">WebAuthn Relying Party</a>'s challenge and
 * OPTIONAL list of credentials it is aware of. This response contains a cryptographic signature proving possession of
 * the <a href="https://www.w3.org/TR/webauthn-3/#credential-private-key">credential private key</a>, and optionally
 * evidence of <a href="https://www.w3.org/TR/webauthn-3/#user-consent">user consent</a> to a specific transaction.
 *
 * @since 6.3
 * @author Rob Winch
 */
public class AuthenticatorAssertionResponse extends AuthenticatorResponse  {

	private final Base64Url authenticatorData;

	private final Base64Url signature;

	private final Base64Url userHandle;

	private final Base64Url attestationObject;

	private AuthenticatorAssertionResponse(Base64Url clientDataJSON, Base64Url authenticatorData, Base64Url signature, Base64Url userHandle, Base64Url attestationObject) {
		super(clientDataJSON);
		this.authenticatorData = authenticatorData;
		this.signature = signature;
		this.userHandle = userHandle;
		this.attestationObject = attestationObject;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-authenticatordata">authenticatorData</a>
	 * contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> returned by
	 * the authenticator. See <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">6.1 Authenticator Data.</a>.
	 * @return the {@code authenticatorData}
	 */
	public Base64Url getAuthenticatorData() {
		return this.authenticatorData;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-signature">signature</a>
	 * contains the raw signature returned from the authenticator. See
	 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">6.3.3 The authenticatorGetAssertion Operation</a>.
	 * @return the {@code signature}
	 */
	public Base64Url getSignature() {
		return this.signature;
	}

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle">userHandle</a>
	 * is the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> which is returned from the
	 * authenticator, or null if the authenticator did not return a user handle. See
	 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">6.3.3 The authenticatorGetAssertion Operation</a>.
	 * The authenticator MUST always return a user handle if the
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a>
	 * option used in the <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>
	 * is empty, and MAY return one otherwise.
	 *
	 * @return the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a>
	 */
	public Base64Url getUserHandle() {
		return this.userHandle;
	}

	/**
	 * The <a href="">attestationObject</a> is an OPTIONAL attribute contains an
	 * <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a>, if the authenticator
	 * supports attestation in assertions.
	 *
	 * @return the {@code attestationObject}
	 */
	public Base64Url getAttestationObject() {
		return this.attestationObject;
	}

	/**
	 * Creates a new {@link AuthenticatorAssertionResponseBuilder}
	 * @return the {@link AuthenticatorAssertionResponseBuilder}
	 */
	public static AuthenticatorAssertionResponseBuilder builder() {
		return new AuthenticatorAssertionResponseBuilder();
	}

	public static final class AuthenticatorAssertionResponseBuilder {
		private Base64Url authenticatorData;
		private Base64Url signature;
		private Base64Url userHandle;
		private Base64Url attestationObject;
		private Base64Url clientDataJSON;

		private AuthenticatorAssertionResponseBuilder() {
		}

		/**
		 * Set the {@link #getAuthenticatorData()} property
		 * @param authenticatorData the authenticator data.
		 * @return the {@link AuthenticatorAssertionResponseBuilder}
		 */
		public AuthenticatorAssertionResponseBuilder authenticatorData(Base64Url authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		/**
		 * Set the {@link #getSignature()} property
		 * @param signature the signature
		 * @return the {@link AuthenticatorAssertionResponseBuilder}
		 */
		public AuthenticatorAssertionResponseBuilder signature(Base64Url signature) {
			this.signature = signature;
			return this;
		}

		/**
		 * Set the {@link #getUserHandle()} property
		 * @param userHandle the user handle
		 * @return the {@link AuthenticatorAssertionResponseBuilder}
		 */
		public AuthenticatorAssertionResponseBuilder userHandle(Base64Url userHandle) {
			this.userHandle = userHandle;
			return this;
		}

		/**
		 * Set the {@link #attestationObject} property
		 * @param attestationObject the attestation object
		 * @return the {@link AuthenticatorAssertionResponseBuilder}
		 */
		public AuthenticatorAssertionResponseBuilder attestationObject(Base64Url attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		/**
		 * Set the {@link #getClientDataJSON()} property
		 * @param clientDataJSON the client data JSON
		 * @return the {@link AuthenticatorAssertionResponseBuilder}
		 */
		public AuthenticatorAssertionResponseBuilder clientDataJSON(Base64Url clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		/**
		 * Builds the {@link AuthenticatorAssertionResponse}
		 * @return the {@link AuthenticatorAssertionResponse}
		 */
		public AuthenticatorAssertionResponse build() {
			return new AuthenticatorAssertionResponse(this.clientDataJSON, this.authenticatorData, this.signature, this.userHandle, this.attestationObject);
		}

	}

}
