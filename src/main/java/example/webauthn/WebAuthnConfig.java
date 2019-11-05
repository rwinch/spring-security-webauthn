package example.webauthn;

import example.webauthn.security.WebAuthnAuthenticatorRepository;
import example.webauthn.security.web.WebAuthnChallengeRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Rob Winch
 */
@Configuration
public class WebAuthnConfig {
	@Bean
	WebAuthnChallengeRepository challengeRepository() {
		return new WebAuthnChallengeRepository();
	}

	@Bean
	WebAuthnAuthenticatorRepository authnAuthenticatorRepository() {
		return new WebAuthnAuthenticatorRepository();
	}
}
