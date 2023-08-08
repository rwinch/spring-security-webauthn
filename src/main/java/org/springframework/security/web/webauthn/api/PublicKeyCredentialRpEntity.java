package org.springframework.security.web.webauthn.api;

public class PublicKeyCredentialRpEntity {
	private final String name;

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
			return new PublicKeyCredentialRpEntity(name, id);
		}
	}
}
