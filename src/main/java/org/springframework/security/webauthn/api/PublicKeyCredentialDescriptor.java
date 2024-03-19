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

import java.util.Arrays;
import java.util.List;

public class PublicKeyCredentialDescriptor {

	private final PublicKeyCredentialType type;

	private final Base64Url id;

	private final List<AuthenticatorTransport> transports;

	private PublicKeyCredentialDescriptor(PublicKeyCredentialType type, Base64Url id, List<AuthenticatorTransport> transports) {
		this.type = type;
		this.id = id;
		this.transports = transports;
	}

	public PublicKeyCredentialType getType() {
		return this.type;
	}

	public Base64Url getId() {
		return this.id;
	}

	public List<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	public static PublicKeyCredentialDescriptorBuilder builder() {
		return new PublicKeyCredentialDescriptorBuilder();
	}

	public static final class PublicKeyCredentialDescriptorBuilder {
		private PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;
		private Base64Url id;
		private List<AuthenticatorTransport> transports;

		private PublicKeyCredentialDescriptorBuilder() {
		}

		public static PublicKeyCredentialDescriptorBuilder builder() {
			return new PublicKeyCredentialDescriptorBuilder();
		}

		public PublicKeyCredentialDescriptorBuilder type(PublicKeyCredentialType type) {
			this.type = type;
			return this;
		}

		public PublicKeyCredentialDescriptorBuilder id(Base64Url id) {
			this.id = id;
			return this;
		}

		public PublicKeyCredentialDescriptorBuilder transports(List<AuthenticatorTransport> transports) {
			this.transports = transports;
			return this;
		}

		public PublicKeyCredentialDescriptorBuilder transports(AuthenticatorTransport... transports) {
			return transports(Arrays.asList(transports));
		}

		public PublicKeyCredentialDescriptor build() {
			return new PublicKeyCredentialDescriptor(this.type, this.id, this.transports);
		}
	}
}
