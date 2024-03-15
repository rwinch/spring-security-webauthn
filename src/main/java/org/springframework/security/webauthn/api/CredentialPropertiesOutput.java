
/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.api;

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
