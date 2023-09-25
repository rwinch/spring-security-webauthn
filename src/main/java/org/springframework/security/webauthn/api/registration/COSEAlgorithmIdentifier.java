package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.COSEAlgorithmIdentifierDeserializer;
import org.springframework.security.webauthn.jackson.COSEAlgorithmIdentifierSerializer;

@JsonSerialize(using = COSEAlgorithmIdentifierSerializer.class) // FIXME: Should externalize the JSON mappings
@JsonDeserialize(using = COSEAlgorithmIdentifierDeserializer.class) // FIXME: SHould externalize
public enum COSEAlgorithmIdentifier {
	EdDSA(-8),
	ES256(-7),
	ES384(-35),
	ES512(-36),
	RS256(-257),
	RS384(-258),
	RS512(-259),
	RS1(-65535);

	private final long value;

	COSEAlgorithmIdentifier(long value) {
		this.value = value;
	}

	public long getValue() {
		return this.value;
	}
}
