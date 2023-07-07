package org.springframework.security.web.webauthn;

import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
public class PublicKeyCredentialCreationOptions {
//	private final PublicKeyCredentialRpEntity rp;
//
//	private final PublicKeyCredentialUserEntity user;
//
//	private final byte[] challenge;
//
//	private final List<PublicKeyCredentialParameters> pubKeyCredParams;
//
//	private final long timeout;
//
//	private final List<PublicCredentialDescriptor> excludeCredentials;
//
//	private final AuthenticatorSelectorCriteria authenticatorSelection;

	public static class PublicKeyCredentialRpEntity {
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
	}

	public static class PublicKeyCredentialUserEntity {
		private final String name;

		private final byte[] id;

		private final String displayName;

		public PublicKeyCredentialUserEntity(String name, byte[] id, String displayName) {
			this.name = name;
			this.id = id;
			this.displayName = displayName;
		}

		public String getName() {
			return this.name;
		}

		public byte[] getId() {
			return this.id;
		}

		public String getDisplayName() {
			return this.displayName;
		}
	}

	public static class PublicKeyCredentialParameters {
		private final String type;

		private final COSEAlgorithmIdentifier alg;

		public PublicKeyCredentialParameters(String type, COSEAlgorithmIdentifier alg) {
			this.type = type;
			this.alg = alg;
		}
	}

	public enum UserVerificationRequirement {
		REQUIRED("required"),
		PREFERRED("preferred"),
		DISCOURAGED("discouraged");

		private final String id;

		UserVerificationRequirement(String id) {
			this.id = id;
		}

		public String getId() {
			return this.id;
		}
	}

	public enum PublicKeyCredentialType {
		PUBLIC_KEY("public-key");

		private final String id;

		PublicKeyCredentialType(String id) {
			this.id = id;
		}

		public String getId() {
			return this.id;
		}
	}

	enum COSEAlgorithmIdentifier {
		ES256(-7),
		ES384(-35),
		ES512(-36),
		EdDSA(-8);

		private final int registryId;

		COSEAlgorithmIdentifier(int registryId) {
			this.registryId = registryId;
		}

		public int getRegistryId() {
			return this.registryId;
		}
	}
}
