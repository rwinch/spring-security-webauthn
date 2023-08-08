package org.springframework.security.web.webauthn.api;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class PublicKeyCredentialParameters {
	public static final PublicKeyCredentialParameters ES512 = new PublicKeyCredentialParameters("public-key", COSEAlgorithmIdentifier.ES512);
	public static final PublicKeyCredentialParameters ES256 = new PublicKeyCredentialParameters("public-key", COSEAlgorithmIdentifier.ES256);
	public static final PublicKeyCredentialParameters RS256 = new PublicKeyCredentialParameters("public-key", COSEAlgorithmIdentifier.RS256);
	private final String type;

	private final COSEAlgorithmIdentifier alg;

	public PublicKeyCredentialParameters(String type, COSEAlgorithmIdentifier alg) {
		this.type = type;
		this.alg = alg;
	}

	public String getType() {
		return this.type;
	}

	public COSEAlgorithmIdentifier getAlg() {
		return this.alg;
	}
}
