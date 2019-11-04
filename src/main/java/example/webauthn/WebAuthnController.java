package example.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * @author Rob Winch
 */
@Controller
public class WebAuthnController {
	final WebAuthnChallengeRepository challenges;

	final WebAuthnAuthenticatorRepository authenticators;

	public WebAuthnController(WebAuthnChallengeRepository challenges,
			WebAuthnAuthenticatorRepository authenticators) {
		this.challenges = challenges;
		this.authenticators = authenticators;
	}

	@GetMapping("/login/webauthn")
	String loginForm(Authentication authentication, HttpSession httpSession, Map<String, Object> model) {
		String challenge = this.challenges.generateChallenge();
		this.challenges.save(httpSession, challenge);
		Authenticator authenticator = this.authenticators.load(authentication);
		model.put("webAuthnChallenge", challenge);
		model.put("credentialId", Base64Utils.encodeToUrlSafeString(authenticator.getAttestedCredentialData().getCredentialId()));
		return "webauthn/login";
	}
}
