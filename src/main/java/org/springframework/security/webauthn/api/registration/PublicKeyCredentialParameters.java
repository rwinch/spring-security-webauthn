package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
 */
public class PublicKeyCredentialParameters {
	public static final PublicKeyCredentialParameters EdDSA = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.EdDSA);
	public static final PublicKeyCredentialParameters ES256 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.ES256);
	public static final PublicKeyCredentialParameters ES384 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.ES384);
	public static final PublicKeyCredentialParameters ES512 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.ES512);
	public static final PublicKeyCredentialParameters RS256 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.RS256);
	public static final PublicKeyCredentialParameters RS384 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.RS384);
	public static final PublicKeyCredentialParameters RS512 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.RS512);
	public static final PublicKeyCredentialParameters RS1 = new PublicKeyCredentialParameters(COSEAlgorithmIdentifier.RS1);


	/**
	 * This member specifies the type of credential to be created. The value SHOULD be a member of
	 * PublicKeyCredentialType but client platforms MUST ignore unknown values, ignoring any
	 * PublicKeyCredentialParameters with an unknown type.
	 */
	private final PublicKeyCredentialType type;

	/**
	 * This member specifies the cryptographic signature algorithm with which the newly generated credential will be
	 * used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
	 */
	private final COSEAlgorithmIdentifier alg;

	public PublicKeyCredentialParameters(COSEAlgorithmIdentifier alg) {
		this(PublicKeyCredentialType.PUBLIC_KEY, alg);
	}
	public PublicKeyCredentialParameters(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg) {
		this.type = type;
		this.alg = alg;
	}

	public PublicKeyCredentialType getType() {
		return this.type;
	}

	public COSEAlgorithmIdentifier getAlg() {
		return this.alg;
	}
}
