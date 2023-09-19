package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.AuthenticationExtensionsClientInput;
import org.springframework.security.webauthn.api.registration.AuthenticationExtensionsClientInputs;

import java.io.IOException;

public class AuthenticationExtensionsClientInputsSerializer extends StdSerializer<AuthenticationExtensionsClientInputs> {


	public AuthenticationExtensionsClientInputsSerializer() {
		super(AuthenticationExtensionsClientInputs.class);
	}

	@Override
	public void serialize(AuthenticationExtensionsClientInputs inputs, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeStartObject();
		for (AuthenticationExtensionsClientInput input : inputs.getInputs()) {
			jgen.writeObjectField(input.getExtensionId(), input.getInput());
		}
		jgen.writeEndObject();
	}
}
