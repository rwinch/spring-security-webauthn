package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

public class CredentialPropertiesOutputDeserializer extends StdDeserializer<CredentialPropertiesOutput> {
	public CredentialPropertiesOutputDeserializer() {
		super(CredentialPropertiesOutput.class);
	}

	@Override
	public CredentialPropertiesOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
		p.nextValue();
		Boolean rk = p.readValueAs(Boolean.class);
		return new CredentialPropertiesOutput(rk);
	}
}
