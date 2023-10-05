package org.springframework.security.webauthn.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;

public class WebAuthnAuthenticationProvider implements AuthenticationProvider {
	private final WebAuthnRelyingPartyOperations relyingPartyOperations;

	private final UserDetailsService userDetailsService;

	public WebAuthnAuthenticationProvider(WebAuthnRelyingPartyOperations relyingPartyOperations, UserDetailsService userDetailsService) {
		this.relyingPartyOperations = relyingPartyOperations;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		WebAuthnAuthenticationRequestToken webAuthnRequest = (WebAuthnAuthenticationRequestToken) authentication;
		String username = this.relyingPartyOperations.authenticate(webAuthnRequest.getWebAuthnRequest());
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
		return UsernamePasswordAuthenticationToken.authenticated(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return WebAuthnAuthenticationRequestToken.class.isAssignableFrom(authentication);
	}
}
