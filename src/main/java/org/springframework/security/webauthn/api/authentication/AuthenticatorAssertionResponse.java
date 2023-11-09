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

package org.springframework.security.webauthn.api.authentication;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.registration.AuthenticatorResponse;

public class AuthenticatorAssertionResponse extends AuthenticatorResponse  {

	private final ArrayBuffer authenticatorData;

	private final ArrayBuffer signature;

	private final ArrayBuffer userHandle;

	private final ArrayBuffer attestationObject;
	public AuthenticatorAssertionResponse(ArrayBuffer clientDataJSON, ArrayBuffer authenticatorData, ArrayBuffer signature, ArrayBuffer userHandle, ArrayBuffer attestationObject) {
		super(clientDataJSON);
		this.authenticatorData = authenticatorData;
		this.signature = signature;
		this.userHandle = userHandle;
		this.attestationObject = attestationObject;
	}

	public ArrayBuffer getAuthenticatorData() {
		return this.authenticatorData;
	}

	public ArrayBuffer getSignature() {
		return this.signature;
	}

	public ArrayBuffer getUserHandle() {
		return this.userHandle;
	}

	public ArrayBuffer getAttestationObject() {
		return this.attestationObject;
	}

	public static AuthenticatorAssertionResponseBuilder builder() {
		return new AuthenticatorAssertionResponseBuilder();
	}


	public static final class AuthenticatorAssertionResponseBuilder {
		private ArrayBuffer authenticatorData;
		private ArrayBuffer signature;
		private ArrayBuffer userHandle;
		private ArrayBuffer attestationObject;
		private ArrayBuffer clientDataJSON;

		private AuthenticatorAssertionResponseBuilder() {
		}

		public static AuthenticatorAssertionResponseBuilder anAuthenticatorAssertionResponse() {
			return new AuthenticatorAssertionResponseBuilder();
		}

		public AuthenticatorAssertionResponseBuilder authenticatorData(ArrayBuffer authenticatorData) {
			this.authenticatorData = authenticatorData;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder signature(ArrayBuffer signature) {
			this.signature = signature;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder userHandle(ArrayBuffer userHandle) {
			this.userHandle = userHandle;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder attestationObject(ArrayBuffer attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		public AuthenticatorAssertionResponseBuilder clientDataJSON(ArrayBuffer clientDataJSON) {
			this.clientDataJSON = clientDataJSON;
			return this;
		}

		public AuthenticatorAssertionResponse build() {
			return new AuthenticatorAssertionResponse(clientDataJSON, authenticatorData, signature, userHandle, attestationObject);
		}
	}
}
