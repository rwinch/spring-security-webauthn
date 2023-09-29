package org.springframework.security.web.webauthn.registration;

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
import org.springframework.security.webauthn.api.registration.*;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class PublicKeyCredentialCreationOptionsFilter extends OncePerRequestFilter {
	private PublicKeyCredentialCreationOptionsRepository repository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	// FIXME: consider require post since changes state
	private RequestMatcher matcher = new AntPathRequestMatcher("/webauthn/registration/options");

	private final WebAuthnRelyingPartyOperations rpOperations;

	private ObjectMapper objectMapper = new ObjectMapper();

	public PublicKeyCredentialCreationOptionsFilter(WebAuthnRelyingPartyOperations rpOperations) {
		this.rpOperations = rpOperations;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		SecurityContext context = SecurityContextHolder.getContext();
		PublicKeyCredentialCreationOptions options = this.rpOperations.createPublicKeyCredentialCreationOptions(context.getAuthentication());
		this.repository.save(request, response, options);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.objectMapper.writeValue(response.getWriter(), options);
	}
}
