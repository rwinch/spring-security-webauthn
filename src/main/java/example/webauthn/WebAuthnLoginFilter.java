package example.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
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
@Component
public class WebAuthnLoginFilter extends OncePerRequestFilter {
	private RequestMatcher matcher = new AntPathRequestMatcher("/login/webauthn",
			"POST");

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final WebAuthnChallengeRepository challenges;

	private final WebAuthnAuthenticatorRepository authenticators;

	public WebAuthnLoginFilter(WebAuthnChallengeRepository challenges,
			WebAuthnAuthenticatorRepository authenticators) {
		this.challenges = challenges;
		this.authenticators = authenticators;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.matcher.matches(request)) {
			login(request);
			this.redirectStrategy.sendRedirect(request, response, "/?success");
			return;
		}
		filterChain.doFilter(request, response);
	}

	private void login(HttpServletRequest request) {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		Authenticator authenticator = this.authenticators.load(authentication);
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}

		// Client properties
		byte[] credentialIdBytes = bytes(request, "credentialId");
		byte[] clientDataJSONBytes = bytes(request, "clientDataJSON");
		byte[] authenticatorDataBytes = bytes(request, "authenticatorData");
		byte[] signatureBytes = bytes(request, "signature");

		// Server properties
		Origin origin = new Origin(request.getScheme(), request.getServerName(), request.getServerPort()); /* set origin */;
		String rpId = origin.getHost();
		String base64Challenge = this.challenges.load(request);
		Challenge challenge = new DefaultChallenge(base64Challenge);
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = false;

		WebAuthnAuthenticationContext authenticationContext =
				new WebAuthnAuthenticationContext(
						credentialIdBytes,
						clientDataJSONBytes,
						authenticatorDataBytes,
						signatureBytes,
						serverProperty,
						userVerificationRequired
				);

		WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator =
				new WebAuthnAuthenticationContextValidator();

		WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator.validate(authenticationContext, authenticator);

		// please update the counter of the authenticator record
		//		updateCounter(
		//				response.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
		//				response.getAuthenticatorData().getSignCount()
		//		);
		authenticator.setCounter(response.getAuthenticatorData().getSignCount());
	}

	private byte[] bytes(HttpServletRequest request, String paramName) {
		String value = request.getParameter(paramName);
		if (value == null) {
			return null;
		}
		return Base64Utils.decodeFromUrlSafeString(value);
	}
}
