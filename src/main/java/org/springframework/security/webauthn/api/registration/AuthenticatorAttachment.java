package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AuthenticatorAttachmentDeserializer;
import org.springframework.security.webauthn.jackson.AuthenticatorAttachmentSerializer;

@JsonDeserialize(using = AuthenticatorAttachmentDeserializer.class)
@JsonSerialize(using = AuthenticatorAttachmentSerializer.class)
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

	public String getValue() {
		return this.value;
	}
}
