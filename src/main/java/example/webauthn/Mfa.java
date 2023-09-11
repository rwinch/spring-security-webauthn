package example.webauthn;

import example.webauthn.security.MultiFactorAuthentication;
import example.webauthn.security.MultiFactorRegistrationRequiredException;
import org.springframework.security.web.webauthn.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * @author Rob Winch
 */
@Component
public class Mfa implements AuthorizationManager<RequestAuthorizationContext> {
	private final MapPublicKeyCredentialUserEntityRepository authenticators;

	public Mfa(MapPublicKeyCredentialUserEntityRepository authenticators) {
		this.authenticators = authenticators;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		if (authentication instanceof AnonymousAuthenticationToken) {
			return new AuthorizationDecision(false);
		}
		if (authentication instanceof MultiFactorAuthentication) {
			return new AuthorizationDecision(false);
		}
//		AuthenticatorAttestationResponse response = this.authenticators.load(authentication.get());
//		if (response == null) {
			throw new MultiFactorRegistrationRequiredException();
//		}
//		throw new MultiFactorAuthenticationRequiredException();
	}
}
