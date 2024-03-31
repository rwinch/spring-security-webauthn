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

import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions;

/**
 * An API for <a href="https://www.w3.org/TR/webauthn-3/#sctn-rp-operations">WebAuthn Relying Party Operations</a>
 * @since 6.3
 * @author Rob Winch
 */
public interface WebAuthnRelyingPartyOperations {

	/**
	 * Creates the {@link PublicKeyCredentialCreationOptions} used to register new credentials.
	 * @param authentication the current {@link Authentication}. It must be authenticated to associate the credential to a user.
	 * @return the {@link PublicKeyCredentialCreationOptions} for the {@link Authentication} passed in. Cannot be null.
	 */
	PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication);

	/**
	 * If {@link RelyingPartyRegistrationRequest} is valid, will register and return a new {@link CredentialRecord}.
	 * @param relyingPartyRegistrationRequest the {@link RelyingPartyRegistrationRequest} to process.
	 * @return a new {@link CredentialRecord}
	 * @throws RuntimeException if the {@link RelyingPartyRegistrationRequest} is not valid.
	 */
	// FIXME: Think about the name RelyingPartyRegistrationRequest (does it align with rfc)
	// FIXME: think about the method name (does it align with rfc)
	CredentialRecord registerCredential(RelyingPartyRegistrationRequest relyingPartyRegistrationRequest);

	/**
	 * Creates the {@link PublicKeyCredentialRequestOptions} used to authenticate a user.
	 * @param authentication the current {@link Authentication}. Possibly null or an anonymous.
	 * @return the {@link PublicKeyCredentialRequestOptions} used to authenticate a user.
	 */
	PublicKeyCredentialRequestOptions createCredentialRequestOptions(Authentication authentication);

	/**
	 * Authenticates the {@link RelyingPartyAuthenticationRequest} passed in
	 * @param request the {@link RelyingPartyAuthenticationRequest}
	 * @return the principal name (e.g. username) if authentication was successful
	 * @throws RuntimeException if authentication fails
	 */
	// FIXME: Think about the name RelyingPartyAuthenticationRequest (does it align with rfc)
	// FIXME: think about the method name (does it align with rfc)
	String authenticate(RelyingPartyAuthenticationRequest request);
}
