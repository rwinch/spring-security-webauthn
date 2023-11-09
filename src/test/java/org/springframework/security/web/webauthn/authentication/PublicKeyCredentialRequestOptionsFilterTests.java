/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.webauthn.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class PublicKeyCredentialRequestOptionsFilterTests {
	@Mock
	private WebAuthnRelyingPartyOperations relyingPartyOperations;

	@Mock
	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		PublicKeyCredentialRequestOptionsFilter filter = new PublicKeyCredentialRequestOptionsFilter(this.relyingPartyOperations);
		filter.setRequestOptionsRepository(this.requestOptionsRepository);
		this.mockMvc = MockMvcBuilders.standaloneSetup()
			.addFilter(filter)
			.build();
	}

	@Test
	void constructorWhenNull() {
		assertThatThrownBy(() -> new PublicKeyCredentialRequestOptionsFilter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void doFilterWhenNoMatch() throws Exception {
		this.mockMvc.perform(get("/nomatch"))
				.andExpect(status().isNotFound())
				.andDo((result) ->
						assertThat(result.getResponse().getContentAsString()).isEmpty()
				);
		verifyNoInteractions(this.relyingPartyOperations, this.requestOptionsRepository);
	}

	@Test
	void doFilterWhenNotGet() throws Exception {
		this.mockMvc.perform(post("/webauthn/authenticate/options"))
				.andExpect(status().isNotFound())
				.andDo((result) ->
						assertThat(result.getResponse().getContentAsString()).isEmpty()
				);
		verifyNoInteractions(this.relyingPartyOperations, this.requestOptionsRepository);
	}

}