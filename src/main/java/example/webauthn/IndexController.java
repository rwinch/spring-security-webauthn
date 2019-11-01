package example.webauthn;

import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * @author Rob Winch
 */
@Controller
public class IndexController {
	final WebAuthnChallengeRepository challenges;

	public IndexController(WebAuthnChallengeRepository challenges) {
		this.challenges = challenges;
	}

	@GetMapping("/")
	String index(Map<String, Object> model, HttpSession httpSession) {
		String challenge = this.challenges.generateChallenge();
		this.challenges.save(httpSession, challenge);
		model.put("webAuthnChallenge", challenge);
		return "webauthn/registration";
	}
}
