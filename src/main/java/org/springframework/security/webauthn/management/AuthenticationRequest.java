package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;

public class AuthenticationRequest {
	private final PublicKeyCredentialRequestOptions requestOptions;

	public AuthenticationRequest(PublicKeyCredentialRequestOptions requestOptions) {
		this.requestOptions = requestOptions;
	}

	public PublicKeyCredentialRequestOptions getRequestOptions() {
		return this.requestOptions;
	}
}
