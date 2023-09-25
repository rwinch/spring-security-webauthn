package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.webauthn.api.registration.COSEAlgorithmIdentifier;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialType;

import java.io.IOException;

public class PublicKeyCredentialTypeDeserializer extends StdDeserializer<PublicKeyCredentialType> {

	public PublicKeyCredentialTypeDeserializer() {
		super(PublicKeyCredentialType.class);
	}

	@Override
	public PublicKeyCredentialType deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		String type = parser.readValueAs(String.class);
		for (PublicKeyCredentialType publicKeyCredentialType : PublicKeyCredentialType.values()) {
			if (publicKeyCredentialType.getValue().equals(type)) {
				return publicKeyCredentialType;
			}
		}
		return null;
	}


}
