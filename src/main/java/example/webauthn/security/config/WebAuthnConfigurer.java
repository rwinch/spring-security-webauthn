package example.webauthn.security.config;

import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.web.webauthn.DefaultWebAuthnLoginPageGeneratingFilter;
import org.springframework.security.web.webauthn.DefaultWebAuthnRegistrationGeneratingFilter;
import org.springframework.security.web.webauthn.MultiFactorExceptionTranslationFilter;
import org.springframework.security.web.webauthn.WebAuthnChallengeRepository;
import org.springframework.security.web.webauthn.WebAuthnLoginFilter;
import org.springframework.security.web.webauthn.WebAuthnRegistrationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Rob Winch
 */
public class WebAuthnConfigurer extends
		AbstractHttpConfigurer<WebAuthnConfigurer, HttpSecurity> {

	public static WebAuthnConfigurer webAuthn() {
		return new WebAuthnConfigurer();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		WebAuthnAuthenticatorRepository authenticators = authnAuthenticatorRepository();
		WebAuthnChallengeRepository challenges = challengeRepository();
		Function<HttpServletRequest, Map<String, String>> csrf = request -> {
			CsrfToken token = (CsrfToken)request.getAttribute(CsrfToken.class.getName());
			return token == null ? Collections.emptyMap() : Collections.singletonMap(token.getParameterName(), token.getToken());
		};
		DefaultWebAuthnRegistrationGeneratingFilter registration = new DefaultWebAuthnRegistrationGeneratingFilter();
		registration.setResolveHiddenInputs(csrf);
		DefaultWebAuthnLoginPageGeneratingFilter login = new DefaultWebAuthnLoginPageGeneratingFilter(
				authenticators);
		login.setResolveHiddenInputs(csrf);
		http
				.addFilterBefore(registration,
						DefaultLoginPageGeneratingFilter.class)
				.addFilterBefore(login,
						DefaultLoginPageGeneratingFilter.class)
				.addFilterAfter(new MultiFactorExceptionTranslationFilter(), ExceptionTranslationFilter.class)
				.addFilterBefore(new WebAuthnRegistrationFilter(challenges, authenticators), UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(new WebAuthnLoginFilter(challenges, authenticators),
						UsernamePasswordAuthenticationFilter.class);
	}

	private WebAuthnChallengeRepository challengeRepository() {
		return new WebAuthnChallengeRepository();
	}

	WebAuthnAuthenticatorRepository authnAuthenticatorRepository() {
		return new WebAuthnAuthenticatorRepository();
	}
}
