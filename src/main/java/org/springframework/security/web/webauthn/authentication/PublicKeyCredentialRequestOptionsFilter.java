package org.springframework.security.web.webauthn.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.management.YubicoWebAuthnRelyingPartyOperations;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class PublicKeyCredentialRequestOptionsFilter extends OncePerRequestFilter {
	private RequestMatcher matcher = new AntPathRequestMatcher("/webauthn/authenticate/options");

	private final YubicoWebAuthnRelyingPartyOperations rpOptions;

	private PublicKeyCredentialRequestOptionsRepository repository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	private final ObjectMapper mapper = new ObjectMapper();

	public PublicKeyCredentialRequestOptionsFilter(YubicoWebAuthnRelyingPartyOperations rpOptions) {
		this.rpOptions = rpOptions;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		SecurityContext context = SecurityContextHolder.getContext();

		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOptions.createCredentialRequestOptions(context.getAuthentication());
		this.repository.save(request, response, credentialRequestOptions);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.mapper.writeValue(response.getWriter(), credentialRequestOptions);

	}
}
