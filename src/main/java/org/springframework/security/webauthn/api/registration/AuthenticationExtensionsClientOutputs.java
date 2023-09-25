package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs
 */
@JsonDeserialize(using = AuthenticationExtensionsClientOutputsDeserializer.class )
public interface AuthenticationExtensionsClientOutputs {
	List<AuthenticationExtensionsClientOutput<?>> getOutputs();
}
