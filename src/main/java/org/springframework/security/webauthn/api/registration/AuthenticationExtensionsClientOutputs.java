
package org.springframework.security.webauthn.api.registration;

import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs
 */
public interface AuthenticationExtensionsClientOutputs {
	List<AuthenticationExtensionsClientOutput<?>> getOutputs();
}
