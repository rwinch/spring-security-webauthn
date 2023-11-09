
package org.springframework.security.webauthn.api.registration;

public class CredentialPropertiesOutput implements AuthenticationExtensionsClientOutput<CredentialPropertiesOutput.ExtensionOutput> {
	public static final String EXTENSION_ID = "credProps";

	private final ExtensionOutput output;

	public CredentialPropertiesOutput(boolean rk) {
		this.output = new ExtensionOutput(rk);
	}

	@Override
	public String getExtensionId() {
		return EXTENSION_ID;
	}

	@Override
	public ExtensionOutput getOutput() {
		return this.output;
	}

	public static final class ExtensionOutput {
		private final boolean rk;

		public ExtensionOutput(boolean rk) {
			this.rk = rk;
		}

		public boolean isRk() {
			return this.rk;
		}
	}
}
