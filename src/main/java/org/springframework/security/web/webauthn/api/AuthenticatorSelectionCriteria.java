package org.springframework.security.web.webauthn.api;

public class AuthenticatorSelectionCriteria {

	private final String authenticatorAttachment;
	private final String residentKey;
	private final boolean requireResidentKey = false;
	private final String userVerification = "preferred";

	public AuthenticatorSelectionCriteria(String authenticatorAttachment, String residentKey) {
		this.authenticatorAttachment = authenticatorAttachment;
		this.residentKey = residentKey;
	}

	public String getAuthenticatorAttachment() {
		return this.authenticatorAttachment;
	}

	public String getResidentKey() {
		return this.residentKey;
	}

	public boolean isRequireResidentKey() {
		return this.requireResidentKey;
	}

	public String getUserVerification() {
		return this.userVerification;
	}
}
