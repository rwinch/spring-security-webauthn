package org.springframework.security.web.webauthn.api;

public class PublicKeyCredentialUserEntity {
	private final String name;

	private final BufferSource id;

	private final String displayName;

	public PublicKeyCredentialUserEntity(String name, BufferSource id, String displayName) {
		this.name = name;
		this.id = id;
		this.displayName = displayName;
	}

	public String getName() {
		return this.name;
	}

	public BufferSource getId() {
		return this.id;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	public static PublicKeyCredentialUserEntityBuilder builder() {
		return new PublicKeyCredentialUserEntityBuilder();
	}

	public static final class PublicKeyCredentialUserEntityBuilder {
		private String name;
		private BufferSource id;
		private String displayName;

		private PublicKeyCredentialUserEntityBuilder() {
		}

		public static PublicKeyCredentialUserEntityBuilder aPublicKeyCredentialUserEntity() {
			return new PublicKeyCredentialUserEntityBuilder();
		}

		public PublicKeyCredentialUserEntityBuilder name(String name) {
			this.name = name;
			return this;
		}

		public PublicKeyCredentialUserEntityBuilder id(BufferSource id) {
			this.id = id;
			return this;
		}

		public PublicKeyCredentialUserEntityBuilder displayName(String displayName) {
			this.displayName = displayName;
			return this;
		}

		public PublicKeyCredentialUserEntity build() {
			return new PublicKeyCredentialUserEntity(name, id, displayName);
		}
	}
}
