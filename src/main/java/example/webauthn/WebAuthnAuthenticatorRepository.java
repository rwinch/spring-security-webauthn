package example.webauthn;

import com.webauthn4j.authenticator.Authenticator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * FIXME: This should be saved per Authentication
 *
 * @author Rob Winch
 */
@Component
public class WebAuthnAuthenticatorRepository {
	private Authenticator authenticator;

	public void save(Authentication authentication, Authenticator authenticator) {
		this.authenticator = authenticator;
	}

	public Authenticator load(Authentication authentication) {
		return this.authenticator;
	}
}
