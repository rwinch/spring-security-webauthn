package org.springframework.security.webauthn.api.registration;

public class ImmutableAuthenticationExtensionsClientInput<T> implements AuthenticationExtensionsClientInput<T> {

	public static final AuthenticationExtensionsClientInput<Boolean> credProps = new ImmutableAuthenticationExtensionsClientInput<>("credProps", true);

	public static final AuthenticationExtensionsClientInput<Boolean> credProtect = new ImmutableAuthenticationExtensionsClientInput<>("credProtect", true);

	private final String extensionId;

	private final T input;


	public ImmutableAuthenticationExtensionsClientInput(String extensionId, T input) {
		this.extensionId = extensionId;
		this.input = input;
	}

	@Override
	public String getExtensionId() {
		return this.extensionId;
	}

	@Override
	public T getInput() {
		return this.input;
	}
}
