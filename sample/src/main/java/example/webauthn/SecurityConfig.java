/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example.webauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.WebauthnConfigurer;
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
				.requestMatchers("/login/**", "/message", "/error").permitAll()
				.anyRequest().authenticated()
			)
			.with(new WebauthnConfigurer<>(), (passkeys) -> passkeys
					.rpName("Spring Security Relying Party")
					.rpId("example.localhost")
					.allowedOrigins("https://example.localhost:8443")
			)
			.oneTimeTokenLogin(c -> c.generatedOneTimeTokenSuccessHandler((request, response, oneTimeToken) -> {
				var msg = "hey, user, you're going to need to go to https://example.localhost:8443/login/ott?token=" + oneTimeToken.getTokenValue();
				System.out.println(msg);
				response.setStatus(HttpStatus.OK.value());
				response.setContentType(MediaType.TEXT_PLAIN_VALUE);
				try (var w = response.getWriter()) {
					w.println("you've got mail!");
				}
			}))
			;
		return http.build();
	}
}
