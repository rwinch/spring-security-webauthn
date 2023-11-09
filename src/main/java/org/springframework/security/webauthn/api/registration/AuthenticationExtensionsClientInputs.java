
package org.springframework.security.webauthn.api.registration;

import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#iface-authentication-extensions-client-inputs
 */
public interface AuthenticationExtensionsClientInputs {
	List<AuthenticationExtensionsClientInput> getInputs();
}
