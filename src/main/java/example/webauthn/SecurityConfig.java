package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.registration.DefaultRegistrationPageGeneratingFilter;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.authentication.WebAuthnAuthenticationProvider;
import org.springframework.security.webauthn.management.*;

import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http, YubicoWebAuthnRelyingPartyOperations rpOperations, UserDetailsService userDetailsService,
			PublicKeyCredentialUserEntityRepository userEntityRepository,
			UserCredentialRepository userCredentials) throws Exception {
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
			.addFilterAfter(new WebAuthnRegistrationFilter(userCredentials, rpOperations), AuthorizationFilter.class)
			.addFilterBefore(new PublicKeyCredentialCreationOptionsFilter(rpOperations), AuthorizationFilter.class)
			.addFilterAfter(new DefaultRegistrationPageGeneratingFilter(userEntityRepository, userCredentials), AuthorizationFilter.class)
			.addFilterBefore(new PublicKeyCredentialRequestOptionsFilter(rpOperations), AuthorizationFilter.class);
		;
		return http.build();
	}

	@Bean
	MapUserCredentialRepository userCredentialRepository() {
		return new MapUserCredentialRepository();
	}

	@Bean
	PublicKeyCredentialUserEntityRepository userEntityRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}

	@Bean
	YubicoWebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities) {
		YubicoWebAuthnRelyingPartyOperations result =  new YubicoWebAuthnRelyingPartyOperations(this.userCredentialRepository(), PublicKeyCredentialRpEntity.builder()
				.id("localhost.example")
				.name("Spring Security Relying Party")
				.build(),
				Set.of("https://localhost.example:8443"));
		result.setUserEntities(userEntities);
		return result;
	}
}
