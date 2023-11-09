package org.springframework.security.webauthn.api.registration;


// FIXME: Verify packages of registration and authentication are correct
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AttestationConveyancePreferenceSerializer;

public enum AttestationConveyancePreference {
	NONE("none"),
	INDIRECT("indirect"),
	DIRECT("direct"),
	ENTERPRISE("enterprise");

	private final String value;

	AttestationConveyancePreference(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
