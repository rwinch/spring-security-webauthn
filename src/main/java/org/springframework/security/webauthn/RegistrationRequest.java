package org.springframework.security.webauthn;

import java.net.URL;

/**
 * @author Rob Winch
 */
public class RegistrationRequest {

	private AuthenticatorAttestationResponse response;

	private ServerRegistrationParameters parameters;

	private URL origin;

	private PublicKeyCredentialCreationOptions creationOptions; // FIXME: think about the name

	public PublicKeyCredentialCreationOptions getCreationOptions() {
		return this.creationOptions;
	}

	public void setCreationOptions(PublicKeyCredentialCreationOptions creationOptions) {
		this.creationOptions = creationOptions;
	}

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
