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

import org.springframework.security.webauthn.api.ArrayBuffer;

/**
 * https://www.w3.org/TR/webauthn-3/#iface-pkcredential
 */
public class PublicKeyCredential<R extends AuthenticatorResponse> {
	/**
	 * This attribute is inherited from Credential, though PublicKeyCredential overrides Credential's getter, instead
	 * returning the base64url encoding of the data contained in the object’s [[identifier]] internal slot.
	 */
	private final String id;

	private final PublicKeyCredentialType type;

	private final ArrayBuffer rawId;

	private final R response;

	private final AuthenticatorAttachment authenticatorAttachment;

	private final AuthenticationExtensionsClientOutputs clientExtensionResults;


	private PublicKeyCredential(String id, PublicKeyCredentialType type, ArrayBuffer rawId, R response, AuthenticatorAttachment authenticatorAttachment, AuthenticationExtensionsClientOutputs clientExtensionResults) {
		this.id = id;
		this.type = type;
		this.rawId = rawId;
		this.response = response;
		this.authenticatorAttachment = authenticatorAttachment;
		this.clientExtensionResults = clientExtensionResults;
	}

	public String getId() {
		return this.id;
	}

	public PublicKeyCredentialType getType() {
		return this.type;
	}

	public ArrayBuffer getRawId() {
		return this.rawId;
	}

	public R getResponse() {
		return this.response;
	}

	public AuthenticationExtensionsClientOutputs getClientExtensionResults() {
		return this.clientExtensionResults;
	}

	public static <T extends AuthenticatorResponse> PublicKeyCredentialBuilder<T> builder() {
		return new PublicKeyCredentialBuilder<T>();
	}

	public static final class PublicKeyCredentialBuilder<R extends AuthenticatorResponse> {
		private String id;
		private PublicKeyCredentialType type;
		private ArrayBuffer rawId;
		private R response;
		private AuthenticatorAttachment authenticatorAttachment;
		private AuthenticationExtensionsClientOutputs clientExtensionResults;

		private PublicKeyCredentialBuilder() {
		}

		public PublicKeyCredentialBuilder id(String id) {
			this.id = id;
			return this;
		}

		public PublicKeyCredentialBuilder type(PublicKeyCredentialType type) {
			this.type = type;
			return this;
		}

		public PublicKeyCredentialBuilder rawId(ArrayBuffer rawId) {
			this.rawId = rawId;
			return this;
		}

		public PublicKeyCredentialBuilder response(R response) {
			this.response = response;
			return this;
		}

		public PublicKeyCredentialBuilder authenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
			this.authenticatorAttachment = authenticatorAttachment;
			return this;
		}

		public PublicKeyCredentialBuilder clientExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
			this.clientExtensionResults = clientExtensionResults;
			return this;
		}

		public PublicKeyCredential<R> build() {
			return new PublicKeyCredential(this.id, this.type, this.rawId, this.response, this.authenticatorAttachment, this.clientExtensionResults);
		}
	}
}
