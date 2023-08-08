package org.springframework.security.web.webauthn.api;

public enum PublicKeyCredentialType {
	PUBLIC_KEY("public-key");

	private final String id;

	PublicKeyCredentialType(String id) {
		this.id = id;
	}

	public String getId() {
		return this.id;
	}
}
