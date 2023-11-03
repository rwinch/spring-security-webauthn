package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttachment;

import java.io.IOException;

public class AuthenticatorAttachmentSerializer extends StdSerializer<AuthenticatorAttachment> {

	public AuthenticatorAttachmentSerializer() {
		super(AuthenticatorAttachment.class);
	}

	@Override
	public void serialize(AuthenticatorAttachment attachment, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(attachment.getValue());
	}
}
