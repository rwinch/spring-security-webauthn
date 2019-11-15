package org.springframework.security.web.webauthn;

import java.net.URL;

/**
 * @author Rob Winch
 */
public class RegistrationRequest {

	private AuthenticatorAttestationResponse response;

	private ServerRegistrationParameters parameters;

	private URL origin;

	public URL getOrigin() {
		return this.origin;
	}

	public void setOrigin(URL origin) {
		this.origin = origin;
	}

	public ServerRegistrationParameters getParameters() {
		return this.parameters;
	}

	public void setParameters(ServerRegistrationParameters parameters) {
		this.parameters = parameters;
	}

	public AuthenticatorAttestationResponse getResponse() {
		return this.response;
	}

	public void setResponse(AuthenticatorAttestationResponse response) {
		this.response = response;
	}
}
