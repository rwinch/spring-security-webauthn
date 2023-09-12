package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.webauthn.MapPublicKeyCredentialUserEntityRepository;

import static org.springframework.security.config.webauthn.WebAuthnConfigurer.webAuthn;

/**
 * @author Rob Winch
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
		http
			.formLogin(Customizer.withDefaults())
			.authorizeHttpRequests(requests -> requests
				.anyRequest().authenticated()
			)
			.apply(webAuthn())
			;
		return http.build();
	}

	@Bean
	public MapPublicKeyCredentialUserEntityRepository authenticatorRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}
}
