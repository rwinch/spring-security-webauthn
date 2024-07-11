/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.api;

/**
 * FIXME: Consider not using an enum. Spec states The AuthenticatorTransport enumeration is deliberately not referenced, see § 2.1.1 Enumerations as DOMString types.
 * <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport">AuthenticatorTransport</a> defines hints
 * as to how clients might communicate with a particular authenticator in order to obtain an assertion for a specific
 * credential.
 *
 * @since 6.4
 * @author Rob Winch
 */
public enum AuthenticatorTransport {

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-usb">usbc</a> indicates the respective
	 * authenticator can be contacted over removable USB.
	 */
	USB("usb"),

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-nfc">nfc</a> indicates the respective
	 * authenticator can be contacted over Near Field Communication (NFC).
	 */
	NFC("nfc"),

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-ble">ble</a> Indicates the respective
	 * authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
	 */
	BLE("ble"),

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-smart-card">smart-card</a> indicates the
	 * respective authenticator can be contacted over ISO/IEC 7816 smart card with contacts.
	 */
	SMART_CARD("smart-card"),

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-hybrid">hybrid</a> indicates the respective
	 * authenticator can be contacted using a combination of (often separate) data-transport and proximity mechanisms.
	 * This supports, for example, authentication on a desktop computer using a smartphone.
	 */
	HYBRID("hybrid"),

	/**
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-internal">internal</a> indicates the
	 * respective authenticator is contacted using a client device-specific transport, i.e., it is a platform
	 * authenticator. These authenticators are not removable from the client device.
	 */
	INTERNAL("internal");

	private final String value;

	AuthenticatorTransport(String value) {
		this.value = value;
	}

	/**
	 * Get's the value.
	 * @return the value.
	 */
	public String getValue() {
		return this.value;
	}

}
