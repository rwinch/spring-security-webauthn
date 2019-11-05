package example.webauthn;

import example.webauthn.security.MultiFactorAuthentication;
import example.webauthn.security.MultiFactorRegistrationRequiredException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * @author Rob Winch
 */
@Component
public class Mfa {
	public boolean require(Authentication authentication) {
		if (authentication instanceof AnonymousAuthenticationToken) {
			return false;
		}
		if (!(authentication instanceof MultiFactorAuthentication)) {
			throw new MultiFactorRegistrationRequiredException();
		}
		return true;
	}
}
