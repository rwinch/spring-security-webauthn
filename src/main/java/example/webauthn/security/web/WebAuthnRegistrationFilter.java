package example.webauthn.security.web;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Rob Winch
 */
public class WebAuthnRegistrationFilter extends OncePerRequestFilter {
	private RequestMatcher matcher = new AntPathRequestMatcher("/webauthn/register",
			"POST");

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final WebAuthnChallengeRepository challenges;

	private final WebAuthnAuthenticatorRepository authenticators;

	public WebAuthnRegistrationFilter(WebAuthnChallengeRepository challenges,
			WebAuthnAuthenticatorRepository authenticators) {
		this.challenges = challenges;
		this.authenticators = authenticators;
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

	private void register(HttpServletRequest request) {

		String clientDataJSON = request.getParameter("clientDataJSON");
		String attestationObject = request.getParameter("attestationObject");

		// Client properties
		byte[] clientDataJSONBytes = Base64Utils.decodeFromUrlSafeString(clientDataJSON);
		byte[] attestationObjectBytes = Base64Utils.decodeFromUrlSafeString(attestationObject);

		// Server properties
		Origin origin = new Origin(request.getScheme(), request.getServerName(), request.getServerPort()); /* set origin */;
		String rpId = origin.getHost();
		String base64Challenge = this.challenges.load(request);
		Challenge challenge = new DefaultChallenge(base64Challenge);
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = false;

		WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJSONBytes, attestationObjectBytes, serverProperty, userVerificationRequired);

		// WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator() returns a WebAuthnRegistrationContextValidator instance
		// which doesn't validate an attestation statement. It is recommended configuration for most web application.
		// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
		// WebAuthnRegistrationContextValidator and provide validators you like
		WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator =
				WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();


		WebAuthnRegistrationContextValidationResponse registration = webAuthnRegistrationContextValidator.validate(registrationContext);
		//
		//		// please persist Authenticator object, which will be used in the authentication process.
		AttestationObject registeredAttestationObject = registration.getAttestationObject();
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = registeredAttestationObject
				.getAuthenticatorData();
		Authenticator authenticator =
				new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
						authenticatorData.getAttestedCredentialData(),
						registeredAttestationObject.getAttestationStatement(),
						authenticatorData.getSignCount()
				);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		this.authenticators.save(authentication, authenticator);
	}
}
