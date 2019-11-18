package org.springframework.security.web.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 *
 * @author Rob Winch
 */
public class WebAuthnManager {
	private SecureRandom random = new SecureRandom();

	private Map<String, byte[]> usernameToUserId = new ConcurrentHashMap<>();

	private final WebAuthnAuthenticatorRepository authenticators;

	public WebAuthnManager(WebAuthnAuthenticatorRepository authenticators) {
		this.authenticators = authenticators;
	}

	public ServerRegistrationParameters createRegistrationParametersFor(Authentication authentication) {
		ServerRegistrationParameters result = new ServerRegistrationParameters();
		result.setChallenge(randomBytes());
		result.setUserId(userId(authentication));
		return result;
	}

	// FIXME: This should return a registration (should not do any saving in the manager)
	public void register(RegistrationRequest request) {
		// Server properties
		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
		String rpId = origin.getHost();
		ServerRegistrationParameters registrationParameters = request.getParameters();
		byte[] base64Challenge = registrationParameters.getChallenge();
		byte[] attestationObject = request.getResponse().getAttestationObject();
		byte[] clientDataJSON = request.getResponse().getClientDataJSON();
		Challenge challenge = new DefaultChallenge(base64Challenge);
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = registrationParameters.isUserVerificationRequired();

		WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJSON, attestationObject, serverProperty, userVerificationRequired);

		// WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator() returns a WebAuthnRegistrationContextValidator instance
		// which doesn't validate an attestation statement. It is recommended configuration for most web application.
		// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
		// WebAuthnRegistrationContextValidator and provide validators you like
		WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator =
				WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();


		WebAuthnRegistrationContextValidationResponse registration = webAuthnRegistrationContextValidator.validate(registrationContext);

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		// FIXME: should save something w/ a counter on it
		this.authenticators.save(authentication, request.getResponse());
	}

	public ServerLoginParameters createLoginParametersFor(Authentication authentication) {
		Authenticator authenticator = this.authenticators.load(authentication);
		ServerLoginParameters result = new ServerLoginParameters();
		result.setChallenge(randomBytes());
		result.setCredentialId(authenticator.getAttestedCredentialData().getCredentialId());
		return result;
	}

	// FIXME: login

	public void login(WebAuthnLoginRequest request) {
		Authenticator authenticator = this.authenticators.load(request.getAuthentication());
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}

		// Client properties

		// Server properties
		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
		String rpId = origin.getHost();
		Challenge challenge = new DefaultChallenge(request.getLoginParameters().getChallenge());
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = false;

		WebAuthnAuthenticationContext authenticationContext =
				new WebAuthnAuthenticationContext(
						request.getCredentialId(),
						request.getClientDataJSON(),
						request.getAuthenticatorData(),
						request.getSignature(),
						serverProperty,
						userVerificationRequired
				);

		WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator =
				new WebAuthnAuthenticationContextValidator();

		WebAuthnAuthenticationContextValidationResponse webauthnResponse = webAuthnAuthenticationContextValidator.validate(authenticationContext, authenticator);

		// please update the counter of the authenticator record
		//		updateCounter(
		//				response.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
		//				response.getAuthenticatorData().getSignCount()
		//		);
		authenticator.setCounter(webauthnResponse.getAuthenticatorData().getSignCount());
	}

	private byte[] userId(Authentication authentication) {
		if (authentication == null) {
			return randomBytes();
		}
		String username = authentication.getName();
		return this.usernameToUserId.computeIfAbsent(username, u -> randomBytes());
	}

	private byte[] randomBytes() {
		byte[] result = new byte[64];
		this.random.nextBytes(result);
		return result;
	}
}
