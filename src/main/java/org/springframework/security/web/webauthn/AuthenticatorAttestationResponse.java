package org.springframework.security.web.webauthn;

/**
 * @author Rob Winch
 */
public class AuthenticatorAttestationResponse {

	private byte[] clientDataJSON;

	private byte[] attestationObject;

	public byte[] getClientDataJSON() {
		return this.clientDataJSON;
	}

	public void setClientDataJSON(byte[] clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public byte[] getAttestationObject() {
		return this.attestationObject;
	}

	public void setAttestationObject(byte[] attestationObject) {
		this.attestationObject = attestationObject;
	}
}
