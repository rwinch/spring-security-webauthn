package org.springframework.security.webauthn.api.registration;

import java.util.ArrayList;
import java.util.List;

public class DefaultAuthenticationExtensionsClientOutputs implements AuthenticationExtensionsClientOutputs {
	private final List<AuthenticationExtensionsClientOutput<?>> outputs = new ArrayList<>();

	public void add(AuthenticationExtensionsClientOutput<?>... outputs) {
		for (AuthenticationExtensionsClientOutput<?> output : outputs) {
			this.outputs.add(output);
		}
	}

	@Override
	public List<AuthenticationExtensionsClientOutput<?>> getOutputs() {
		return this.outputs;
	}
}
