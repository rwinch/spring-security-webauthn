package org.springframework.security.web.webauthn.registration;

import com.yubico.internal.util.JacksonCodecs;
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
import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.management.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private final WebAuthnRelyingPartyOperations rpOptions;
	private final UserCredentialRepository userCredentials;
	private GenericHttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();
	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private RequestMatcher matcher = antMatcher(HttpMethod.POST, "/webauthn/register");

	private RequestMatcher removeCredentialMatcher = antMatcher(HttpMethod.POST, "/webauthn/register/{id}");

	public WebAuthnRegistrationFilter(UserCredentialRepository userCredentials, WebAuthnRelyingPartyOperations rpOptions) {
		this.userCredentials = userCredentials;
		this.rpOptions = rpOptions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (this.matcher.matches(request)) {
			registerCredential(request, response);
			return;
		}
		RequestMatcher.MatchResult matcher = this.removeCredentialMatcher.matcher(request);
		if (matcher.isMatch()) {
			String id = matcher.getVariables().get("id");
			removeCredential(request, response, id);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void registerCredential(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
		// FIXME: Read RegistrationRequest(PublicKeyCredential,String label)
		RelyingPartyRequest relyingPartyRequest = (RelyingPartyRequest) this.converter.read(RelyingPartyRequest.class, getClass(), inputMessage);
		PublicKeyCredentialCreationOptions options = this.creationOptionsRepository.load(request);
		this.rpOptions.registerCredential(new RelyingPartyRegistrationRequest(options, relyingPartyRequest.getPublicKey()));
		response.getWriter().write("{ \"verified\": \"true\" }");
	}

	private void removeCredential(HttpServletRequest request, HttpServletResponse response, String id) throws IOException {
		this.userCredentials.delete(ArrayBuffer.fromBase64(id));
		response.sendRedirect("/webauthn/register?success");
	}

	// FIXME: make private
	public static class RelyingPartyRequest {
		private RelyingPartyPublicKey publicKey;

		public RelyingPartyPublicKey getPublicKey() {
			return this.publicKey;
		}

		public void setPublicKey(RelyingPartyPublicKey publicKey) {
			this.publicKey = publicKey;
		}
	}
}
