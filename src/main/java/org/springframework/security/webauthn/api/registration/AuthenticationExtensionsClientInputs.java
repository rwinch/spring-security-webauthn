package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer;

import java.util.List;

@JsonSerialize(using = AuthenticationExtensionsClientInputsSerializer.class)
public interface AuthenticationExtensionsClientInputs {
	List<AuthenticationExtensionsClientInput> getInputs();
}
