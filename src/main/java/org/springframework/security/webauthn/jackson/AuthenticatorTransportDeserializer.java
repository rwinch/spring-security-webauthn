/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.AuthenticatorTransport;
import org.springframework.security.webauthn.api.PublicKeyCredentialType;

import java.io.IOException;

/**
 * Jackson deserializer for {@link AuthenticatorTransport}
 * @since 6.3
 * @author Rob Winch
 */
class AuthenticatorTransportDeserializer extends StdDeserializer<AuthenticatorTransport> {

	AuthenticatorTransportDeserializer() {
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
