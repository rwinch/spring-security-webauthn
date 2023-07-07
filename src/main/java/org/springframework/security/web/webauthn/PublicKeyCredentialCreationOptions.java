package org.springframework.security.web.webauthn;

public class PublicKeyCredentialCreationOptions {
	private final byte[] challenge;

	private final UserInfo userInfo;

	private final RelyingPartyInfo relyingPartyInfo;

	public PublicKeyCredentialCreationOptions(byte[] challenge, UserInfo userInfo, RelyingPartyInfo relyingPartyInfo) {
		this.challenge = challenge;
		this.userInfo = userInfo;
		this.relyingPartyInfo = relyingPartyInfo;
	}

	public byte[] getChallenge() {
		return this.challenge;
	}

	public UserInfo getUserInfo() {
		return this.userInfo;
	}

	public RelyingPartyInfo getRelyingPartyInfo() {
		return this.relyingPartyInfo;
	}

	public static class UserInfo {

	}

	public static class RelyingPartyInfo {

	}
}
