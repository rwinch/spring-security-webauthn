package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.springframework.security.webauthn.api.core.ArrayBuffer;

/**
 * https://www.w3.org/TR/webauthn-3/#iface-pkcredential
 */

@JsonDeserialize(builder = PublicKeyCredential.PublicKeyCredentialBuilder.class)  // FIXME: Externalize JsonDeserialize
public class PublicKeyCredential<R extends AuthenticatorResponse> {
	/**
	 * This attribute is inherited from Credential, though PublicKeyCredential overrides Credential's getter, instead
	 * returning the base64url encoding of the data contained in the object’s [[identifier]] internal slot.
	 */
	private final String id;

	private final PublicKeyCredentialType type;

	private final ArrayBuffer rawId;

	private final R response;

	private final AuthenticationExtensionsClientOutputs clientExtensionResults;

	// FIXME: Figure out if this needs to have authenticatorAttachment property too. It isn't listed in the spec as far as I can tell, but it is in the body of the request from SimpleWebAuthn


	private PublicKeyCredential(String id, PublicKeyCredentialType type, ArrayBuffer rawId, R response, AuthenticationExtensionsClientOutputs clientExtensionResults) {
		this.id = id;
		this.type = type;
		this.rawId = rawId;
		this.response = response;
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

	@JsonPOJOBuilder(withPrefix = "") // FIXME: Externalize JsonPOJOBuilder
	public static final class PublicKeyCredentialBuilder<R extends AuthenticatorResponse> {
		private String id;
		private PublicKeyCredentialType type;
		private ArrayBuffer rawId;
		private R response;
		private AuthenticationExtensionsClientOutputs clientExtensionResults;

		private PublicKeyCredentialBuilder() {
		}

		public static PublicKeyCredentialBuilder aPublicKeyCredential() {
			return new PublicKeyCredentialBuilder();
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

		public PublicKeyCredentialBuilder clientExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
			this.clientExtensionResults = clientExtensionResults;
			return this;
		}

		public PublicKeyCredential<R> build() {
			return new PublicKeyCredential(this.id, this.type, this.rawId, this.response, this.clientExtensionResults);
		}
	}
}
