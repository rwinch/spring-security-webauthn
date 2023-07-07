package example.webauthn;

import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

import static example.webauthn.security.config.WebAuthnConfigurer.webAuthn;

/**
 * @author Rob Winch
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http, Mfa mfa) throws Exception {
		http
			.formLogin(Customizer.withDefaults())
			.authorizeHttpRequests(requests -> requests
				.requestMatchers("/secure").access(mfa)
				.anyRequest().authenticated()
			)
			.apply(webAuthn())
			;
		return http.build();
	}

	@Bean
	public WebAuthnAuthenticatorRepository authenticatorRepository() {
		return new WebAuthnAuthenticatorRepository();
	}
}
