package org.springframework.security.webauthn.api.registration;

import org.springframework.security.webauthn.api.core.ArrayBuffer;

public class AuthenticatorResponse {
	private final ArrayBuffer clientDataJSON;

	public AuthenticatorResponse(ArrayBuffer clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public ArrayBuffer getClientDataJSON() {
		return this.clientDataJSON;
	}
}
