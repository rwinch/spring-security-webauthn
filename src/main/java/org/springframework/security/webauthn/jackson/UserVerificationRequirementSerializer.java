package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.registration.ResidentKeyRequirement;
import org.springframework.security.webauthn.api.registration.UserVerificationRequirement;

import java.io.IOException;

public class UserVerificationRequirementSerializer extends StdSerializer<UserVerificationRequirement> {

	public UserVerificationRequirementSerializer() {
		super(UserVerificationRequirement.class);
	}

	@Override
	public void serialize(UserVerificationRequirement requirement, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(requirement.getValue());
	}
}
