package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.webauthn.jackson.AuthenticatorTransportDeserializer;

@JsonDeserialize(using = AuthenticatorTransportDeserializer.class)
public enum AuthenticatorTransport {
	USB("usb"),
	NFC("nfc"),
	BLE("ble"),
	HYBRID("hybrid"),
	INTERNAL("internal");

	private final String value;

	AuthenticatorTransport(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
