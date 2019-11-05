package example.webauthn;

import example.webauthn.security.WebAuthnAuthenticatorRepository;
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
		http
			.addFilterAfter(new MultiFactorExceptionTranslationFilter(), ExceptionTranslationFilter.class)
			.addFilterBefore(new WebAuthnRegistrationFilter(this.challenges, this.authenticators), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new WebAuthnLoginFilter(this.challenges, this.authenticators),
					UsernamePasswordAuthenticationFilter.class)
			.formLogin().and()
			.authorizeRequests()
				.mvcMatchers("/login/webauthn", "/base64url.js").permitAll()
				.mvcMatchers("/webauthn/register").authenticated()
				.anyRequest().access("@mfa.require(authentication)");
	}
}
