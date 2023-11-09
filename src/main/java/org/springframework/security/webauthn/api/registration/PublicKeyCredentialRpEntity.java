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

package org.springframework.security.webauthn.api.registration;

/**
 * https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity
 */
public class PublicKeyCredentialRpEntity {
	/**
	 * A human-palatable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
	 *
	 * When inherited by PublicKeyCredentialRpEntity it is a human-palatable identifier for the Relying Party, intended
	 * only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
	 * <p>
	 * Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for the Nickname Profile of
	 * the PRECIS FreeformClass [RFC8264], when setting name's value, or displaying the value to the user.
	 * <p>
	 * This string MAY contain language and direction metadata. Relying Parties SHOULD consider providing this
	 * information. See § 6.4.2 Language and Direction Encoding about how this metadata is encoded.
	 * <p>
	 * Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for the Nickname Profile of the
	 * PRECIS FreeformClass [RFC8264], on name's value prior to displaying the value to the user or including the value
	 * as a parameter of the authenticatorMakeCredential operation.
	 */
	private final String name;

	/**
	 * A unique identifier for the Relying Party entity, which sets the RP ID.
	 */
	private final String id;

	public PublicKeyCredentialRpEntity(String name, String id) {
		this.name = name;
		this.id = id;
	}

	public String getName() {
		return this.name;
	}

	public String getId() {
		return this.id;
	}

	public static PublicKeyCredentialRpEntityBuilder builder() {
		return new PublicKeyCredentialRpEntityBuilder();
	}


	public static final class PublicKeyCredentialRpEntityBuilder {
		private String name;
		private String id;

		private PublicKeyCredentialRpEntityBuilder() {
		}

		public static PublicKeyCredentialRpEntityBuilder aPublicKeyCredentialRpEntity() {
			return new PublicKeyCredentialRpEntityBuilder();
		}

		public PublicKeyCredentialRpEntityBuilder name(String name) {
			this.name = name;
			return this;
		}

		public PublicKeyCredentialRpEntityBuilder id(String id) {
			this.id = id;
			return this;
		}

		public PublicKeyCredentialRpEntity build() {
			return new PublicKeyCredentialRpEntity(this.name, this.id);
		}
	}
}
