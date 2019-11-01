package example.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
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
import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.Map;

/**
 * @author Rob Winch
 */
@Controller
public class WebAuthnController {
	final WebAuthnChallengeRepository challenges;

	Authenticator authenticator;

	public WebAuthnController(WebAuthnChallengeRepository challenges) {
		this.challenges = challenges;
	}

	@PostMapping("/webauthn/register")
	String registration(HttpServletRequest request,
			Principal principal,
			@RequestParam String clientDataJSON,
			@RequestParam String attestationObject,
			@RequestParam String clientExtensions) {

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


		WebAuthnRegistrationContextValidationResponse response = webAuthnRegistrationContextValidator.validate(registrationContext);
//
//		// please persist Authenticator object, which will be used in the authentication process.
		this.authenticator =
				new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
						response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
						response.getAttestationObject().getAttestationStatement(),
						response.getAttestationObject().getAuthenticatorData().getSignCount()
				);

		return "redirect:/login/webauthn";
	}

	@GetMapping("/login/webauthn")
	String loginForm(HttpSession httpSession, Map<String, Object> model) {
		String challenge = this.challenges.generateChallenge();
		this.challenges.save(httpSession, challenge);
		model.put("webAuthnChallenge", challenge);
		model.put("credentialId", Base64Utils.encodeToUrlSafeString(this.authenticator.getAttestedCredentialData().getCredentialId()));
		return "webauthn/login";
	}

	@PostMapping("/login/webauthn")
	String login(HttpServletRequest request,
			@RequestParam String credentialId,
			@RequestParam String clientDataJSON,
			@RequestParam String authenticatorData,
			@RequestParam String signature,
			@RequestParam String clientExtensions) {
		if (this.authenticator == null) {
			return "redirect:/?please-register";
		}

		// Client properties
		byte[] credentialIdBytes = Base64Utils.decodeFromUrlSafeString(credentialId);
		byte[] clientDataJSONBytes = Base64Utils.decodeFromUrlSafeString(clientDataJSON);
		byte[] authenticatorDataBytes = Base64Utils.decodeFromUrlSafeString(authenticatorData);
		byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

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
		Authenticator authenticator = this.authenticator; // please load authenticator object persisted in the registration process in your manner

		WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator =
				new WebAuthnAuthenticationContextValidator();

		WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator.validate(authenticationContext, authenticator);

		// please update the counter of the authenticator record
//		updateCounter(
//				response.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
//				response.getAuthenticatorData().getSignCount()
//		);
		this.authenticator.setCounter(response.getAuthenticatorData().getSignCount());

		return "redirect:/?login";
	}
}
