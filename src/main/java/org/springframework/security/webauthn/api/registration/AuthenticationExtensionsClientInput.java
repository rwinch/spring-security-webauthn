package org.springframework.security.webauthn.api.registration;

/**
 *
 * @param <T>
 */
public interface AuthenticationExtensionsClientInput<T> {
	String getExtensionId();

	T getInput();
}
