package org.springframework.security.webauthn.api.registration;


import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.data.AuthenticatorDataFlags;
import org.springframework.security.webauthn.jackson.UserVerificationRequirementSerializer;

@JsonSerialize(using = UserVerificationRequirementSerializer.class)
public enum UserVerificationRequirement {

	/**
	 * This value indicates that the Relying Party does not want user verification employed during the
	 * operation (e.g., in the interest of minimizing disruption to the user interaction flow).
	 */
	DISCOURAGED("discouraged"),

	/**
	 * This value indicates that the Relying Party prefers user verification for the operation if
	 * possible, but will not fail the operation if the response does not have the {@link
	 * AuthenticatorDataFlags#UV} flag set.
	 *
	 * FIXME: AuthenticatorDataFlags is a type from yubico
	 */
	PREFERRED("preferred"),

	/**
	 * Indicates that the Relying Party requires user verification for the operation and will fail the
	 * operation if the response does not have the {@link AuthenticatorDataFlags#UV} flag set.
	 */
	REQUIRED("required");

	private final String value;

	UserVerificationRequirement(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}