
package org.springframework.security.webauthn.api.registration;

public enum PublicKeyCredentialType {
	PUBLIC_KEY("public-key");

	private final String value;

	PublicKeyCredentialType(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
