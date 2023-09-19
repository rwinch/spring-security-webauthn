package org.springframework.security.webauthn.api.registration;

import java.util.ArrayList;
import java.util.List;

public class DefaultAuthenticationExtensionsClientInputs implements AuthenticationExtensionsClientInputs {
	private final List<AuthenticationExtensionsClientInput> inputs = new ArrayList<>();

	public void add(AuthenticationExtensionsClientInput... inputs) {
		for (AuthenticationExtensionsClientInput input : inputs) {
			this.inputs.add(input);
		}
	}
	@Override
	public List<AuthenticationExtensionsClientInput> getInputs() {
		return this.inputs;
	}
}
