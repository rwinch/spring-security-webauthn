package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.AttestationConveyancePreference;
import org.springframework.security.webauthn.api.registration.ResidentKeyRequirement;

import java.io.IOException;

public class AttestationConveyancePreferenceSerializer extends StdSerializer<AttestationConveyancePreference> {

	public AttestationConveyancePreferenceSerializer() {
		super(AttestationConveyancePreference.class);
	}

	@Override
	public void serialize(AttestationConveyancePreference preference, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(preference.getValue());
	}
}
