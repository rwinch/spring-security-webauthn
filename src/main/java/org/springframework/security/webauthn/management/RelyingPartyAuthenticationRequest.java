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

package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.PublicKeyCredential;
import org.springframework.util.Assert;

/**
 * The data object used to provide the information necessary to authenticate a user with WebAuthn.
 *
 * @see WebAuthnRelyingPartyOperations#authenticate(RelyingPartyAuthenticationRequest)
 * @since 6.3
 * @author Rob Winch
 */
public class RelyingPartyAuthenticationRequest {

	private final PublicKeyCredentialRequestOptions requestOptions;

	private final PublicKeyCredential<AuthenticatorAssertionResponse> publicKey;

	/**
	 * Creates a new instance.
	 * @param requestOptions the {@link PublicKeyCredentialRequestOptions}
	 * @param publicKey the {@link PublicKeyCredential}
	 */
	public RelyingPartyAuthenticationRequest(PublicKeyCredentialRequestOptions requestOptions, PublicKeyCredential<AuthenticatorAssertionResponse> publicKey) {
		Assert.notNull(requestOptions, "requestOptions cannot be null");
		Assert.notNull(publicKey, "publicKey cannot be null");
		this.requestOptions = requestOptions;
		this.publicKey = publicKey;
	}

	/**
	 * Ges the request options.
	 * @return the request options.
	 */
	public PublicKeyCredentialRequestOptions getRequestOptions() {
		return this.requestOptions;
	}

	/**
	 * Gets the public key.
	 * @return the public key.
	 */
	public PublicKeyCredential<AuthenticatorAssertionResponse> getPublicKey() {
		return this.publicKey;
	}

}
