package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.PublicKeyCredentialTypeSerializer;

@JsonSerialize(using = PublicKeyCredentialTypeSerializer.class) // FIXME: This should be externalized rather than configured inline
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
