/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
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
		try {
			String username = this.relyingPartyOperations.authenticate(webAuthnRequest.getWebAuthnRequest());
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
			return UsernamePasswordAuthenticationToken.authenticated(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
		}
		catch (RuntimeException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return WebAuthnAuthenticationRequestToken.class.isAssignableFrom(authentication);
	}
}
