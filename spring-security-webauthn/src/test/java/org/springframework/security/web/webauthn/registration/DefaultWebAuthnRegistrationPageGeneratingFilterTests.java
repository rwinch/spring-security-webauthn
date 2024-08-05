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
import org.springframework.security.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.api.TestCredentialRecord;
import org.springframework.security.webauthn.api.Bytes;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.management.ImmutableCredentialRecord;
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
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(TestCredentialRecord.userCredential().build()));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}");
		assertThat(body.replaceAll("\\s", "")).contains("""
			<form class="delete-form" method="post" action="/webauthn/register/NauGCN7bZ5jEBwThcde51g">
				<input type="hidden" name="method" value="delete">
				<input type="hidden" name="_csrf" value="CSRF_TOKEN">
				<button class="btn btn-sm btn-primary btn-block" type="submit">Delete</button>
			</form>""".replaceAll("\\s", ""));
	}

	@Test
	void doFilterWhenNullPublicKeyCredentialUserEntityThenNoResults() throws Exception {
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verifyNoInteractions(this.userCredentials);
	}

	@Test
	void doFilterWhenNoCredentialsThenNoResults() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Collections.emptyList());
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verify(this.userCredentials).findByUserId(any());
	}

	@Test
	void doFilterWhenResultsThenDisplayed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains(credential.getLabel());
		assertThat(body).contains(credential.getCreated().toString());
		assertThat(body).contains(credential.getLastUsed().toString());
		assertThat(body).contains(String.valueOf(credential.getSignatureCount()));
		assertThat(body).contains(credential.getCredentialId().toBase64UrlString());
	}

	@Test
	void doFilterWhenResultsContainEntitiesThenEncoded() throws Exception {
		String label = "<script>alert('Hello');</script>";
		String htmlEncodedLabel = HtmlUtils.htmlEscape(label);
		assertThat(label).isNotEqualTo(htmlEncodedLabel);
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential()
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
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("<script type=\"text/javascript\" src=\"/login/webauthn.js\"></script>");
		assertThat(body).contains("document.addEventListener(\"DOMContentLoaded\",() => setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}, \"\",");
	}

	@Test
	void doFilterWhenContextNotEmptyThenUrlsPrefixed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(Bytes.random())
				.displayName("User")
				.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().build();
		when(this.userEntities.findByUsername(any())).thenReturn(userEntity);
		when(this.userCredentials.findByUserId(userEntity.getId())).thenReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest("/foo"));
		assertThat(body).contains("<script type=\"text/javascript\" src=\"/foo/login/webauthn.js\"></script>");
		assertThat(body).contains("setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}, \"/foo\",");
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
