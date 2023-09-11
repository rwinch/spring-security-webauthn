package org.springframework.security.web.webauthn;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Base64;

/**
 * @author Rob Winch
 */
public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private RequestMatcher matcher = new AntPathRequestMatcher("/webauthn/register",
			"POST");

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final WebAuthnManager manager;

	private WebAuthnParamsRepository webAuthnRequests = new WebAuthnParamsRepository();

	private PublicKeyCredentialCreationOptionsRepository optionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	public WebAuthnRegistrationFilter(WebAuthnManager manager) {
		this.manager = manager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.matcher.matches(request)) {
			register(request);
			this.redirectStrategy.sendRedirect(request, response, "/login/webauthn");
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void register(HttpServletRequest request) throws IOException{

		String clientDataJSON = request.getParameter("clientDataJSON");
		String attestationObject = request.getParameter("attestationObject");

		byte[] attestationObjectBytes = Base64.getDecoder().decode(attestationObject);
		//FIXME: clientExtensionJSON should also be received


		ServerRegistrationParameters parameters = this.webAuthnRequests.loadRegistrationParams(request);
		PublicKeyCredentialCreationOptions options = this.optionsRepository.load(request);
		AuthenticatorAttestationResponse authenticatorResponse = new AuthenticatorAttestationResponse();
		authenticatorResponse.setAttestationObject(attestationObjectBytes);
		authenticatorResponse.setClientDataJSON(clientDataJSON);
		RegistrationRequest registration = new RegistrationRequest();
		registration.setResponse(authenticatorResponse);
		registration.setParameters(parameters);
		registration.setOrigin(new URL(request.getRequestURL().toString()));
		registration.setCreationOptions(options);

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		this.manager.register(registration, authentication);
	}
}
