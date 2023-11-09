package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.PasskeysConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
		http
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults())
			.authorizeHttpRequests(requests -> requests
				.requestMatchers("/login/**").permitAll()
				.anyRequest().authenticated()
			)
			.with(new PasskeysConfigurer<>(), Customizer.withDefaults());
		return http.build();
	}
}
