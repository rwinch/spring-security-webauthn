package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.authentication.WebAuthnAuthenticationProvider;
import org.springframework.security.webauthn.management.YubicoWebAuthnRelyingPartyOperations;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http, YubicoWebAuthnRelyingPartyOperations rpOperations, UserDetailsService userDetailsService) throws Exception {
		WebAuthnAuthenticationFilter webAuthnAuthnFilter = new WebAuthnAuthenticationFilter();
		webAuthnAuthnFilter.setAuthenticationManager(new ProviderManager(new WebAuthnAuthenticationProvider(rpOperations, userDetailsService)));
		http
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults())
			.authorizeHttpRequests(requests -> requests
				.requestMatchers("/login/**").permitAll()
				.anyRequest().authenticated()
			)
			.addFilterBefore(webAuthnAuthnFilter, BasicAuthenticationFilter.class)
			.addFilterAfter(new WebAuthnRegistrationFilter(rpOperations), FilterSecurityInterceptor.class)
			.addFilterBefore(new PublicKeyCredentialCreationOptionsFilter(rpOperations), DefaultLoginPageGeneratingFilter.class)
			.addFilterBefore(new PublicKeyCredentialRequestOptionsFilter(rpOperations), DefaultLoginPageGeneratingFilter.class);
		;
		return http.build();
	}

	@Bean
	YubicoWebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
		return new YubicoWebAuthnRelyingPartyOperations(PublicKeyCredentialRpEntity.builder()
				.id("localhost")
				.name("Spring Security Relying Party")
				.build());
	}
}
