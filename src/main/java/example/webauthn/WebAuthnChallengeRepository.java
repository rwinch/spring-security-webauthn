package example.webauthn;

import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * @author Rob Winch
 */
@Component
public class WebAuthnChallengeRepository {

	private String attrName = "challenge";

	public String generateChallenge() {
		return Base64Utils.encodeToUrlSafeString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
	}

	public void save(HttpSession httpSession, String challenge) {
		httpSession.setAttribute(this.attrName, challenge);
	}

	public String load(HttpServletRequest request) {
		return (String) request.getSession().getAttribute(this.attrName);
	}
}
