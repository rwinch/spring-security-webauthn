package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;

public class RelyingPartyRegistrationRequest {

	private final PublicKeyCredentialCreationOptions options;

	private final RelyingPartyPublicKey publicKey;


	public RelyingPartyRegistrationRequest(PublicKeyCredentialCreationOptions options, RelyingPartyPublicKey publicKey) {
		this.options = options;
		this.publicKey = publicKey;
	}

	public PublicKeyCredentialCreationOptions getCreationOptions() {
		return this.options;
	}

	public RelyingPartyPublicKey getPublicKey() {
		return this.publicKey;
	}
}
