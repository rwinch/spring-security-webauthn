package org.springframework.security.web.webauthn.api;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = COSEAlgorithmIdentifierSerializer.class)
public enum COSEAlgorithmIdentifier {
	ES256(-7),
	ES384(-35),
	ES512(-36),
	EdDSA(-8),
	RS256(-257);

	private final int registryId;

	COSEAlgorithmIdentifier(int registryId) {
		this.registryId = registryId;
	}

	public int getRegistryId() {
		return this.registryId;
	}
}
