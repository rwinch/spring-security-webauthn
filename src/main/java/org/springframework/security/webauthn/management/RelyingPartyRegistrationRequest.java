package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;

public class RelyingPartyRegistrationRequest {

	private final PublicKeyCredentialCreationOptions options;

	private final PublicKeyCredential<AuthenticatorAttestationResponse> credential;


	public RelyingPartyRegistrationRequest(PublicKeyCredentialCreationOptions options, PublicKeyCredential<AuthenticatorAttestationResponse> credential) {
		this.options = options;
		this.credential = credential;
	}

	public PublicKeyCredentialCreationOptions getCreationOptions() {
		return this.options;
	}

	public PublicKeyCredential<AuthenticatorAttestationResponse> getCredential() {
		return this.credential;
	}
}
