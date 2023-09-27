package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;

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
				// FIXME: create DSL and change the location
				.addFilterBefore(new PublicKeyCredentialCreationOptionsFilter(), DefaultLoginPageGeneratingFilter.class)
				.addFilterBefore(new PublicKeyCredentialRequestOptionsFilter(), DefaultLoginPageGeneratingFilter.class);
		;
		return http.build();
	}
}
