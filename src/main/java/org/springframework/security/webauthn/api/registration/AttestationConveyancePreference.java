package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AttestationConveyancePreferenceSerializer;

@JsonSerialize(using = AttestationConveyancePreferenceSerializer.class)
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
