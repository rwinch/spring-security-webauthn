package org.springframework.security.webauthn;

/**
 * @author Rob Winch
 */
public class AuthenticatorAttestationResponse {

	private String clientDataJSON;

	private byte[] attestationObject;

	public String getClientDataJSON() {
		return this.clientDataJSON;
	}

	public void setClientDataJSON(String clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public byte[] getAttestationObject() {
		return this.attestationObject;
	}

	public void setAttestationObject(byte[] attestationObject) {
		this.attestationObject = attestationObject;
	}
}
