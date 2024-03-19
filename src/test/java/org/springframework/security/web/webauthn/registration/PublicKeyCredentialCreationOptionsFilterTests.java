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

package org.springframework.security.web.webauthn.registration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.AuthenticatorTransport;
import org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for {@link PublicKeyCredentialCreationOptionsFilter}.
 *
 * @since 6.3
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
class PublicKeyCredentialCreationOptionsFilterTests {

	private static String REGISTER_OPTONS_URL = "/webauthn/register/options";

	@Mock
	private WebAuthnRelyingPartyOperations rpOperations;

	@AfterEach
	void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void constructorWhenRpOperationsIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new PublicKeyCredentialCreationOptionsFilter(null))
			.withMessage("rpOperations cannot be null");
	}

	@Test
	void doFilterWhenWrongUrlThenNoInteractions() throws Exception {
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(post("/foo"));
		verifyNoInteractions(this.rpOperations);
	}

	@Test
	void doFilterWhenNotAuthenticatedThenNoInvocations() throws Exception {
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(post(REGISTER_OPTONS_URL));
		verifyNoInteractions(this.rpOperations);
	}

	@Test
	void doFilterWhenAnonymousThenNoInvocations() throws Exception {
		AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		SecurityContextImpl context = new SecurityContextImpl(anonymous);
		SecurityContextHolder.setContext(context);
		doFilterWhenWrongUrlThenNoInteractions();
	}

	@Test
	void doFilterWhenGetThenNoInteractions() throws Exception {
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(get(REGISTER_OPTONS_URL));
		verifyNoInteractions(this.rpOperations);
	}

	@Test
	void doFilterWhenNoCredentials() throws Exception {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
				.createPublicKeyCredentialCreationOptions()
				.build();
		when(this.rpOperations.createPublicKeyCredentialCreationOptions(any())).thenReturn(options);
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(matchingRequest())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
				.andExpect(status().isOk())
				.andExpect(content().json("""
		{
			"rp": {
				"name": "SimpleWebAuthn Example",
				"id": "example.localhost"
			},
			"user": {
				"name": "user@example.localhost",
				"id": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w",
				"displayName": "user@example.localhost"
			},
			"challenge": "q7lCdd3SVQxdC-v8pnRAGEn1B2M-t7ZECWPwCAmhWvc",
			"pubKeyCredParams": [
				{
					"type": "public-key",
					"alg": -257
				},
				{
					"type": "public-key",
					"alg": -7
				}
			],
			"timeout": 60000,
			"excludeCredentials": [],
			"authenticatorSelection": {
				"residentKey": "discouraged",
				"userVerification": "preferred"
			},
			"attestation": "none",
			"extensions": {
				"credProps": true
			}
		}
"""));
	}

	@Test
	void doFilterWhenExcludeCredentialsThenIncludedInResponse() throws Exception {
		PublicKeyCredentialDescriptor credentialDescriptor = PublicKeyCredentialDescriptor.builder()
			.transports(AuthenticatorTransport.HYBRID)
			.id(Base64Url.fromBase64("ChfoCM8CJA_wwUGDdzdtuw"))
			.build();
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.excludeCredentials(Arrays.asList(credentialDescriptor))
			.build();
		when(this.rpOperations.createPublicKeyCredentialCreationOptions(any())).thenReturn(options);
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(matchingRequest())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
				.andExpect(status().isOk())
				.andExpect(content().json("""
		{
			"excludeCredentials": [
				{
					"type": "public-key",
					"id": "ChfoCM8CJA_wwUGDdzdtuw",
					"transports": [
						"HYBRID"
					]
				}
			]
		}
"""));
	}

	private MockHttpServletRequestBuilder matchingRequest() {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.setContext(new SecurityContextImpl(user));
		return post(REGISTER_OPTONS_URL);
	}

	private MockMvc mockMvc() {
		return MockMvcBuilders
				.standaloneSetup(new Object())
				.addFilter(new PublicKeyCredentialCreationOptionsFilter(this.rpOperations))
				.build();
	}
}