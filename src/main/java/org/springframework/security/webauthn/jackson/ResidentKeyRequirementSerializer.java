package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.ResidentKeyRequirement;

import java.io.IOException;
import java.util.Base64;

public class ResidentKeyRequirementSerializer extends StdSerializer<ResidentKeyRequirement> {

	public ResidentKeyRequirementSerializer() {
		super(ResidentKeyRequirement.class);
	}

	@Override
	public void serialize(ResidentKeyRequirement requirement, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(requirement.getValue());
	}
}
