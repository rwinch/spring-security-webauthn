package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.AttestationConveyancePreference;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialType;

import java.io.IOException;

public class PublicKeyCredentialTypeSerializer extends StdSerializer<PublicKeyCredentialType> {

	public PublicKeyCredentialTypeSerializer() {
		super(PublicKeyCredentialType.class);
	}

	@Override
	public void serialize(PublicKeyCredentialType type, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(type.getValue());
	}
}
