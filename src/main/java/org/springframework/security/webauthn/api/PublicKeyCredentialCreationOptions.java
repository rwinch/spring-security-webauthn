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

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Represents the
 * <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a>
 * which is an argument to
 * <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">creating</a> a
 * new credential.
 */
public class PublicKeyCredentialCreationOptions {
	/**
	 * This member contains data about the Relying Party responsible for the request.
	 *
	 * Its value’s name member is REQUIRED. See §5.4.1 Public Key Entity Description (dictionary
	 * PublicKeyCredentialEntity) for further details.
	 *
	 * Its value’s id member specifies the RP ID the credential should be scoped to. If omitted, its value will be the
	 * CredentialsContainer object’s relevant settings object's origin's effective domain. See §5.4.2 Relying Party
	 * Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity) for further details.
	 */
	private final PublicKeyCredentialRpEntity rp;

	/**
	 * This member contains data about the user account for which the Relying Party is requesting attestation.
	 *
	 * Its value’s name, displayName and id members are REQUIRED. See §5.4.1 Public Key Entity Description
	 * (dictionary PublicKeyCredentialEntity) and §5.4.3 User Account Parameters for Credential Generation
	 * (dictionary PublicKeyCredentialUserEntity) for further details.
	 */
	private final PublicKeyCredentialUserEntity user;

	/**
	 * This member contains a challenge intended to be used for generating the newly created credential’s attestation
	 * object. See the §13.4.3 Cryptographic Challenges security consideration.
	 */
	private final Base64Url challenge;

	/**
	 * This member contains information about the desired properties of the credential to be created. The sequence is
	 * ordered from most preferred to least preferred. The client makes a best-effort to create the most preferred
	 * credential that it can.
	 */
	private final List<PublicKeyCredentialParameters> pubKeyCredParams;

	private Duration timeout;

	private final List<PublicKeyCredentialDescriptor> excludeCredentials;

	private final AuthenticatorSelectionCriteria authenticatorSelection;

	/**
	 * This member is intended for use by Relying Parties that wish to express their preference for attestation
	 * conveyance. Its values SHOULD be members of AttestationConveyancePreference. Client platforms MUST ignore unknown
	 * values, treating an unknown value as if the member does not exist. Its default value is "none".
	 */
	private AttestationConveyancePreference attestation = AttestationConveyancePreference.NONE;

	private final AuthenticationExtensionsClientInputs extensions;

	private PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user,
											   Base64Url challenge, List<PublicKeyCredentialParameters> pubKeyCredParams,
											   List<PublicKeyCredentialDescriptor> excludeCredentials, AuthenticatorSelectionCriteria authenticatorSelection,
											   AuthenticationExtensionsClientInputs extensions) {
		this.rp = rp;
		this.user = user;
		this.challenge = challenge;
		this.pubKeyCredParams = pubKeyCredParams;
		this.excludeCredentials = excludeCredentials;
		this.authenticatorSelection = authenticatorSelection;
		this.extensions = extensions;
	}

	public PublicKeyCredentialRpEntity getRp() {
		return this.rp;
	}

	public PublicKeyCredentialUserEntity getUser() {
		return this.user;
	}

	public Base64Url getChallenge() {
		return this.challenge;
	}

	public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
		return this.pubKeyCredParams;
	}

	public Duration getTimeout() {
		return this.timeout;
	}

	public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
		return this.excludeCredentials;
	}

	public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
		return this.authenticatorSelection;
	}

	public AttestationConveyancePreference getAttestation() {
		return this.attestation;
	}

	public AuthenticationExtensionsClientInputs getExtensions() {
		return this.extensions;
	}

	public static PublicKeyCredentialCreationOptionsBuilder builder() {
		return new PublicKeyCredentialCreationOptionsBuilder();
	}

	public static final class PublicKeyCredentialCreationOptionsBuilder {
		private PublicKeyCredentialRpEntity rp;
		private PublicKeyCredentialUserEntity user;
		private Base64Url challenge;
		private List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
		private Duration timeout;
		private List<PublicKeyCredentialDescriptor> excludeCredentials = new ArrayList<>();
		private AuthenticatorSelectionCriteria authenticatorSelection;
		private AttestationConveyancePreference attestation;
		private AuthenticationExtensionsClientInputs extensions;

		private PublicKeyCredentialCreationOptionsBuilder() {
		}

		public static PublicKeyCredentialCreationOptionsBuilder aPublicKeyCredentialCreationOptions() {
			return new PublicKeyCredentialCreationOptionsBuilder();
		}

		public PublicKeyCredentialCreationOptionsBuilder rp(PublicKeyCredentialRpEntity rp) {
			this.rp = rp;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder user(PublicKeyCredentialUserEntity user) {
			this.user = user;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder challenge(Base64Url challenge) {
			this.challenge = challenge;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder pubKeyCredParams(PublicKeyCredentialParameters... pubKeyCredParams) {
			return pubKeyCredParams(Arrays.asList(pubKeyCredParams));
		}

		public PublicKeyCredentialCreationOptionsBuilder pubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) {
			this.pubKeyCredParams = pubKeyCredParams;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder timeout(Duration timeout) {
			this.timeout = timeout;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder excludeCredentials(List<PublicKeyCredentialDescriptor> excludeCredentials) {
			this.excludeCredentials = excludeCredentials;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder authenticatorSelection(AuthenticatorSelectionCriteria authenticatorSelection) {
			this.authenticatorSelection = authenticatorSelection;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder attestation(AttestationConveyancePreference attestation) {
			this.attestation = attestation;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder extensions(AuthenticationExtensionsClientInputs extensions) {
			this.extensions = extensions;
			return this;
		}

		public PublicKeyCredentialCreationOptions build() {
			PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(this.rp, this.user, this.challenge, this.pubKeyCredParams, this.excludeCredentials, this.authenticatorSelection, this.extensions);
			publicKeyCredentialCreationOptions.timeout = this.timeout;
			publicKeyCredentialCreationOptions.attestation = this.attestation;
			return publicKeyCredentialCreationOptions;
		}
	}
}
