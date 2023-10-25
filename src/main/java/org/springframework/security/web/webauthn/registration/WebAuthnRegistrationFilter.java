package org.springframework.security.web.webauthn.registration;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.management.RelyingPartyRegistrationRequest;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private final WebAuthnRelyingPartyOperations rpOptions;
	private GenericHttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();
	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private RequestMatcher matcher = antMatcher(HttpMethod.POST, "/webauthn/register");

	public WebAuthnRegistrationFilter(WebAuthnRelyingPartyOperations rpOptions) {
		this.rpOptions = rpOptions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		JavaType type = TypeFactory.defaultInstance().constructParametricType(PublicKeyCredential.class, AuthenticatorAttestationResponse.class);
		HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
		// FIXME: Read RegistrationRequest(PublicKeyCredential,String label)
		PublicKeyCredential<AuthenticatorAttestationResponse> credentials = (PublicKeyCredential<AuthenticatorAttestationResponse>) this.converter.read(type, getClass(), inputMessage);
		PublicKeyCredentialCreationOptions options = this.creationOptionsRepository.load(request);
		this.rpOptions.registerCredential(new RelyingPartyRegistrationRequest(options, credentials));
		response.getWriter().write("{ \"verified\": \"true\" }");
	}
}
