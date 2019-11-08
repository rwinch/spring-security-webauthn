package example.webauthn;

import example.webauthn.security.WebAuthnAuthenticatorRepository;
import example.webauthn.security.web.DefaultWebAuthnLoginPageGeneratingFilter;
import example.webauthn.security.web.DefaultWebAuthnRegistrationGeneratingFilter;
import example.webauthn.security.web.MultiFactorExceptionTranslationFilter;
import example.webauthn.security.web.WebAuthnChallengeRepository;
import example.webauthn.security.web.WebAuthnLoginFilter;
import example.webauthn.security.web.WebAuthnRegistrationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private WebAuthnChallengeRepository challenges;

	@Autowired
	private WebAuthnAuthenticatorRepository authenticators;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
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
			.addFilterBefore(new WebAuthnRegistrationFilter(this.challenges, this.authenticators), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new WebAuthnLoginFilter(this.challenges, this.authenticators),
					UsernamePasswordAuthenticationFilter.class)
			.formLogin().and()
			.authorizeRequests()
				.mvcMatchers("/login/webauthn", "/base64url.js").permitAll()
				.mvcMatchers("/secure").access("@mfa.require(authentication)")
				.anyRequest().authenticated();
	}
}
