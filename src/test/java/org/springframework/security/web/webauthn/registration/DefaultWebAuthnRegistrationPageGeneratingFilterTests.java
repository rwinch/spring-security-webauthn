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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.webauthn.api.TestUserCredential;
import org.springframework.security.webauthn.api.BufferSource;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.management.ImmutableUserCredential;
import org.springframework.security.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.webauthn.management.UserCredentialRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.HtmlUtils;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(MockitoExtension.class)
class DefaultWebAuthnRegistrationPageGeneratingFilterTests {

	@Mock
	private PublicKeyCredentialUserEntityRepository userEntities;

	@Mock
	private UserCredentialRepository userCredentials;

	@Test
	void constructorWhenNullUserEntities() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DefaultWebAuthnRegistrationPageGeneratingFilter(null, this.userCredentials))
				.withMessage("userEntities cannot be null");
	}

	@Test
	void constructorWhenNullUserCredentials() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DefaultWebAuthnRegistrationPageGeneratingFilter(this.userEntities, null))
				.withMessage("userCredentials cannot be null");
	}

	@Test
	void doFilterWhenNotMatchThenNoInteractions() throws Exception{
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(get("/not-match"));

		verifyNoInteractions(this.userEntities, this.userCredentials);
	}

	@Test
	void doFilterThenCsrfDataAttrsPresent() throws Exception {
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(TestUserCredential.userCredential().build()));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("data-csrf-token=\"CSRF_TOKEN\"");
		assertThat(body).contains("data-csrf-header-name=\"X-CSRF-TOKEN\"");
		assertThat(body).contains("<input type=\"hidden\" name=\"_csrf\" value=\"CSRF_TOKEN\">");
	}

	@Test
	void doFilterWhenNullPublicKeyCredentialUserEntityThenNoResults() throws Exception {
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verifyNoInteractions(this.userCredentials);
	}

	@Test
	void doFilterWhenNoCredentialsThenNoResults() throws Exception {
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Collections.emptyList());
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verify(this.userCredentials).findByUserId(any());
	}

	@Test
	void doFilterWhenResultsThenDisplayed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		ImmutableUserCredential credential = TestUserCredential.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains(credential.getLabel());
		assertThat(body).contains(credential.getCreated().toString());
		assertThat(body).contains(credential.getLastUsed().toString());
		assertThat(body).contains(credential.getCredentialId().getBytesAsBase64());
	}

	@Test
	void doFilterWhenResultsContainEntitiesThenEncoded() throws Exception {
		String label = "<script>alert('Hello');</script>";
		String htmlEncodedLabel = HtmlUtils.htmlEscape(label);
		assertThat(label).isNotEqualTo(htmlEncodedLabel);
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		ImmutableUserCredential credential = TestUserCredential.userCredential()
			.label(label)
			.build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).doesNotContain(credential.getLabel());
		assertThat(body).contains(htmlEncodedLabel);
	}

	@Test
	void doFilterWhenSuccessThenMessage() throws Exception {
		String body = bodyAsString(matchingRequest().param("success", ""));
		assertThat(body).contains("Success!");
	}

	@Test
	void doFilterWhenNotSuccessThenNoMessage() throws Exception {
		String body = bodyAsString(matchingRequest());
		assertThat(body).doesNotContain("Success!");
	}

	@Test
	void doFilterWhenContextEmptyThenUrlsEmptyPrefix() throws Exception {
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		ImmutableUserCredential credential = TestUserCredential.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("await fetch('/webauthn/register', {");
		assertThat(body).contains("await fetch('/webauthn/register/options', {");
		assertThat(body).contains("window.location.href = '/webauthn/register?success'");
		assertThat(body).contains(String.format("action=\"/webauthn/register/%s\"", credential.getCredentialId().getBytesAsBase64()));
	}

	@Test
	void doFilterWhenContextNotEmptyThenUrlsPrefixed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity("user", BufferSource.random(), "User");
		ImmutableUserCredential credential = TestUserCredential.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest("/foo"));
		assertThat(body).contains("await fetch('/foo/webauthn/register', {");
		assertThat(body).contains("await fetch('/foo/webauthn/register/options', {");
		assertThat(body).contains("window.location.href = '/foo/webauthn/register?success'");
		assertThat(body).contains(String.format("action=\"/foo/webauthn/register/%s\"", credential.getCredentialId().getBytesAsBase64()));
	}

	private String bodyAsString(RequestBuilder request) throws Exception {
		MockMvc mockMvc = mockMvc();
		MvcResult result = mockMvc.perform(request).andReturn();
		MockHttpServletResponse response = result.getResponse();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		return response.getContentAsString();
	}

	private MockHttpServletRequestBuilder matchingRequest() {
		return matchingRequest("");
	}

	private MockHttpServletRequestBuilder matchingRequest(String contextPath) {
		DefaultCsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "CSRF_TOKEN");
		return get(contextPath + "/webauthn/register")
			.contextPath(contextPath)
			.requestAttr(CsrfToken.class.getName(), token);
	}

	private MockMvc mockMvc() {
		return MockMvcBuilders
				.standaloneSetup(new Object())
				.addFilter(new DefaultWebAuthnRegistrationPageGeneratingFilter(this.userEntities, this.userCredentials))
				.build();
	}
}