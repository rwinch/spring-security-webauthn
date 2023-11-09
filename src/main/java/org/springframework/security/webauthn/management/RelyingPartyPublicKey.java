package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;

public class RelyingPartyPublicKey {

	private final PublicKeyCredential<AuthenticatorAttestationResponse> credential;

	private final String label;

	public RelyingPartyPublicKey(PublicKeyCredential<AuthenticatorAttestationResponse> credential, String label) {
		this.credential = credential;
		this.label = label;
	}

	public PublicKeyCredential<AuthenticatorAttestationResponse> getCredential() {
		return this.credential;
	}

	public String getLabel() {
		return this.label;
	}
}
