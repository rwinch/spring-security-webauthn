package org.springframework.security.webauthn.api.registration;

public interface AuthenticationExtensionsClientOutput<T> {
	String getExtensionId();

	T getOutput();
}
