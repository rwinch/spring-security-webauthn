package org.springframework.security.webauthn.api.registration;

public enum AuthenticatorAttachment {

	/**
	 * Indicates <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#cross-platform-attachment">cross-platform
	 * attachment</a>.
	 *
	 * <p>Authenticators of this class are removable from, and can "roam" among, client platforms.
	 */
	CROSS_PLATFORM("cross-platform"),

	/**
	 * Indicates <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#platform-attachment">platform
	 * attachment</a>.
	 *
	 * <p>Usually, authenticators of this class are not removable from the platform.
	 */
	PLATFORM("platform");

	private final String value;

	AuthenticatorAttachment(String value) {
		this.value = value;
	}
}
