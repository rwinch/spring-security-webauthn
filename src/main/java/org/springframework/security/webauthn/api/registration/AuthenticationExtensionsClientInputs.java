package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer;

import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#iface-authentication-extensions-client-inputs
 */
@JsonSerialize(using = AuthenticationExtensionsClientInputsSerializer.class)
public interface AuthenticationExtensionsClientInputs {
	List<AuthenticationExtensionsClientInput> getInputs();
}
