package org.springframework.security.web.webauthn.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public class PublicKeyCredentialRequestOptionsFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = antMatcher(HttpMethod.GET,"/webauthn/authenticate/options");

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final WebAuthnRelyingPartyOperations rpOptions;

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	private final ObjectMapper mapper = new ObjectMapper();

	public PublicKeyCredentialRequestOptionsFilter(WebAuthnRelyingPartyOperations rpOptions) {
		Assert.notNull(rpOptions, "rpOperations cannot be null");
		this.rpOptions = rpOptions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		SecurityContext context = this.securityContextHolderStrategy.getContext();

		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOptions.createCredentialRequestOptions(context.getAuthentication());
		this.requestOptionsRepository.save(request, response, credentialRequestOptions);
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.mapper.writeValue(response.getWriter(), credentialRequestOptions);

	}

	public void setRequestOptionsRepository(PublicKeyCredentialRequestOptionsRepository requestOptionsRepository) {
		Assert.notNull(requestOptionsRepository, "requestOptionsRepository cannot be null");
		this.requestOptionsRepository = requestOptionsRepository;
	}

}
