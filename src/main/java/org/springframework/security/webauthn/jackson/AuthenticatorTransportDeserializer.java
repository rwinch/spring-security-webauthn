package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.AuthenticatorTransport;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialType;

import java.io.IOException;

public class AuthenticatorTransportDeserializer extends StdDeserializer<AuthenticatorTransport> {

	public AuthenticatorTransportDeserializer() {
		super(AuthenticatorTransport.class);
	}

	@Override
	public AuthenticatorTransport deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {
		String transportValue = parser.readValueAs(String.class);
		for (AuthenticatorTransport transport : AuthenticatorTransport.values()) {
			if (transport.getValue().equals(transportValue)) {
				return transport;
			}
		}
		return null;
	}


}
