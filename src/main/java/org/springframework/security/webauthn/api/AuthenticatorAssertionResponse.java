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

public class AuthenticatorAssertionResponse extends AuthenticatorResponse  {

	private final Base64Url authenticatorData;

	private final Base64Url signature;

	private final Base64Url userHandle;

	private final Base64Url attestationObject;
	public AuthenticatorAssertionResponse(Base64Url clientDataJSON, Base64Url authenticatorData, Base64Url signature, Base64Url userHandle, Base64Url attestationObject) {
		super(clientDataJSON);
		this.authenticatorData = authenticatorData;
		this.signature = signature;
		this.userHandle = userHandle;
		this.attestationObject = attestationObject;
	}

	public Base64Url getAuthenticatorData() {
		return this.authenticatorData;
	}

	public Base64Url getSignature() {
		return this.signature;
	}

	public Base64Url getUserHandle() {
		return this.userHandle;
	}

	public Base64Url getAttestationObject() {
		return this.attestationObject;
	}

	public static AuthenticatorAssertionResponseBuilder builder() {
		return new AuthenticatorAssertionResponseBuilder();
	}


	public static final class AuthenticatorAssertionResponseBuilder {
		private Base64Url authenticatorData;
		private Base64Url signature;
		private Base64Url userHandle;
		private Base64Url attestationObject;
		private Base64Url clientDataJSON;

		private AuthenticatorAssertionResponseBuilder() {
		}

		public static AuthenticatorAssertionResponseBuilder anAuthenticatorAssertionResponse() {
			return new AuthenticatorAssertionResponseBuilder();
		}

		public AuthenticatorAssertionResponseBuilder authenticatorData(Base64Url authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder signature(Base64Url signature) {
			this.signature = signature;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder userHandle(Base64Url userHandle) {
			this.userHandle = userHandle;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder attestationObject(Base64Url attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder clientDataJSON(Base64Url clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		public AuthenticatorAssertionResponse build() {
			return new AuthenticatorAssertionResponse(clientDataJSON, authenticatorData, signature, userHandle, attestationObject);
		}
	}
}
