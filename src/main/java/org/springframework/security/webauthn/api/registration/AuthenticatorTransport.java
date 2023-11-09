
package org.springframework.security.webauthn.api.registration;

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
