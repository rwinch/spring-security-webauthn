package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.webauthn.api.registration.AuthenticatorTransport;
import org.springframework.security.webauthn.api.registration.COSEAlgorithmIdentifier;

import java.io.IOException;

public class COSEAlgorithmIdentifierDeserializer extends StdDeserializer<COSEAlgorithmIdentifier> {

	public COSEAlgorithmIdentifierDeserializer() {
		super(COSEAlgorithmIdentifier.class);
	}

	@Override
	public COSEAlgorithmIdentifier deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		Long transportValue = parser.readValueAs(Long.class);
		for (COSEAlgorithmIdentifier identifier : COSEAlgorithmIdentifier.values()) {
			if (identifier.getValue() == transportValue.longValue()) {
				return identifier;
			}
		}
		return null;
	}


}
