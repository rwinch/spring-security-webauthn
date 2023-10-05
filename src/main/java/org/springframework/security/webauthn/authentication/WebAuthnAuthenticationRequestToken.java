package org.springframework.security.webauthn.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.webauthn.management.AuthenticationRequest;
import org.springframework.util.Assert;

public class WebAuthnAuthenticationRequestToken extends AbstractAuthenticationToken {
	private final AuthenticationRequest webAuthnRequest;

	public WebAuthnAuthenticationRequestToken(AuthenticationRequest webAuthnRequest) {
		super(AuthorityUtils.NO_AUTHORITIES);
		this.webAuthnRequest = webAuthnRequest;
	}

	public AuthenticationRequest getWebAuthnRequest() {
		return this.webAuthnRequest;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		Assert.isTrue(!authenticated,
				"Cannot set this token to trusted");
		super.setAuthenticated(authenticated);
	}

	@Override
	public Object getCredentials() {
		return this.webAuthnRequest.getPublicKey();
	}

	@Override
	public Object getPrincipal() {
		return this.webAuthnRequest.getPublicKey().getResponse().getUserHandle();
	}
}
