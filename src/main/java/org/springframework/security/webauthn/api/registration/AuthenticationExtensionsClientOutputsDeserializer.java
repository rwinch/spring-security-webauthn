package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.Map;

public class AuthenticationExtensionsClientOutputsDeserializer extends StdDeserializer<AuthenticationExtensionsClientOutputs> {
	public AuthenticationExtensionsClientOutputsDeserializer() {
		super(AuthenticationExtensionsClientOutputs.class);
	}
	@Override
	public AuthenticationExtensionsClientOutputs deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		DefaultAuthenticationExtensionsClientOutputs result = new DefaultAuthenticationExtensionsClientOutputs();
		for (String key = parser.nextFieldName(); key != null; key = parser.nextFieldName()) {
			parser.nextValue();
			if (CredentialPropertiesOutput.EXTENSION_ID.equals(key)) {
				CredentialPropertiesOutput output = parser.readValueAs(CredentialPropertiesOutput.class);
				result.add(output);
			}
			else {
				throw new IllegalArgumentException("Cannot process extension with id " + key);
			}
		}

		return result;
	}
}