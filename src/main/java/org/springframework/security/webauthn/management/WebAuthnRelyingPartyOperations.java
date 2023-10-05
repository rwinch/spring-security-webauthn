package org.springframework.security.webauthn.management;

import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;

public interface WebAuthnRelyingPartyOperations {
	// FIXME: Pass in the host (can have an allow list), perhaps pass PublicKeyCredentialUserEntity
	PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication);

	void registerCredential(RelyingPartyRegistrationRequest relyingPartyRegistrationRequest);

	PublicKeyCredentialRequestOptions createCredentialRequestOptions(Authentication authentication);

	String authenticate(AuthenticationRequest request);
}
