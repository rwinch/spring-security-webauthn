package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttachment;

import java.io.IOException;

public class AuthenticatorAttachmentDeserializer extends StdDeserializer<AuthenticatorAttachment> {

	public AuthenticatorAttachmentDeserializer() {
		super(AuthenticatorAttachment.class);
	}

	@Override
	public AuthenticatorAttachment deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		String type = parser.readValueAs(String.class);
		for (AuthenticatorAttachment publicKeyCredentialType : AuthenticatorAttachment.values()) {
			if (publicKeyCredentialType.getValue().equals(type)) {
				return publicKeyCredentialType;
			}
		}
		return null;
	}


}
