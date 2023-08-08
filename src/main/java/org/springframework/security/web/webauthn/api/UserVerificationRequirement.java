package org.springframework.security.web.webauthn.api;

public enum UserVerificationRequirement {
	REQUIRED("required"),
	PREFERRED("preferred"),
	DISCOURAGED("discouraged");

	private final String id;

	UserVerificationRequirement(String id) {
		this.id = id;
	}

	public String getId() {
		return this.id;
	}
}
