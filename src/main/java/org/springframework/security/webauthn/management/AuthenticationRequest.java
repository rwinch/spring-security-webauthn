package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;

public class AuthenticationRequest {
	private final PublicKeyCredentialRequestOptions requestOptions;

	private final PublicKeyCredential<AuthenticatorAssertionResponse> publicKey;

	public AuthenticationRequest(PublicKeyCredentialRequestOptions requestOptions, PublicKeyCredential<AuthenticatorAssertionResponse> publicKey) {
		this.requestOptions = requestOptions;
		this.publicKey = publicKey;
	}

	public PublicKeyCredentialRequestOptions getRequestOptions() {
		return this.requestOptions;
	}

	public PublicKeyCredential<AuthenticatorAssertionResponse> getPublicKey() {
		return this.publicKey;
	}
}
