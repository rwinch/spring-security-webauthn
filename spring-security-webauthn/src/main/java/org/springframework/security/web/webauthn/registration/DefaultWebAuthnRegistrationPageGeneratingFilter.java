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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.management.CredentialRecord;
import org.springframework.security.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.webauthn.management.UserCredentialRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A {@link jakarta.servlet.Filter} that renders a default WebAuthn registration page.
 *
 * @author Rob Winch
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
public class DefaultWebAuthnRegistrationPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/webauthn/register");

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	/**
	 * Creates a new instance.
	 * @param userEntities the {@link PublicKeyCredentialUserEntity}
	 * @param userCredentials
	 */
	public DefaultWebAuthnRegistrationPageGeneratingFilter(PublicKeyCredentialUserEntityRepository userEntities,
			UserCredentialRepository userCredentials) {
		Assert.notNull(userEntities, "userEntities cannot be null");
		Assert.notNull(userCredentials, "userCredentials cannot be null");
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		boolean success = request.getParameterMap().containsKey("success");

		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.setStatus(HttpServletResponse.SC_OK);
		String processedTemplate = HtmlTemplates.fromTemplate(HTML_TEMPLATE)
			.withValue("contextPath", request.getContextPath())
			.withRawHtml("message", success ? SUCCESS_MESSAGE : "")
			.withRawHtml("csrfHeaders", renderCsrfHeader(csrfToken))
			.withRawHtml("passkeys", passkeyRows(request.getRemoteUser(), request.getContextPath(), csrfToken))
			.render();

		response.getWriter().write(processedTemplate);
	}

	private String passkeyRows(String username, String contextPath, CsrfToken csrfToken) {
		PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(username);
		List<CredentialRecord> credentials = userEntity == null ? Collections.emptyList()
				: this.userCredentials.findByUserId(userEntity.getId());
		if (credentials.isEmpty()) {
			return """
					<tr><td colspan="5">No Passkeys</td></tr>
					""";
		}
		return credentials.stream()
			.map(credentialRecord -> renderPasskeyRow(credentialRecord, contextPath, csrfToken))
			.collect(Collectors.joining("\n"));
	}

	private String renderPasskeyRow(CredentialRecord credential, String contextPath, CsrfToken csrfToken) {
		return HtmlTemplates.fromTemplate(PASSKEY_ROW_TEMPLATE)
			.withValue("label", credential.getLabel())
			.withValue("created", credential.getCreated())
			.withValue("lastUsed", credential.getLastUsed())
			.withValue("signatureCount", credential.getSignatureCount())
			.withValue("credentialId", credential.getCredentialId().toBase64UrlString())
			.withValue("csrfParameterName", csrfToken.getParameterName())
			.withValue("csrfToken", csrfToken.getToken())
			.withValue("contextPath", contextPath)
			.render();
	}

	private String renderCsrfHeader(CsrfToken csrfToken) {
		return HtmlTemplates.fromTemplate(CSRF_HEADERS)
			.withValue("headerName", csrfToken.getHeaderName())
			.withValue("headerValue", csrfToken.getToken())
			.render();
	}

	private static final String HTML_TEMPLATE = """
			<html>
				<head>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
					<meta name="description" content="">
					<meta name="author" content="">
					<title>WebAuthn Registration</title>
					<link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
					<link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
					<script type="text/javascript" src="{{contextPath}}/login/webauthn.js"></script>
					<script type="text/javascript">
					<!--
						const ui = {
							getRegisterButton: function() {
								return document.getElementById('register')
							},
							getSuccess: function() {
								return document.getElementById('success')
							},
							getError: function() {
								return document.getElementById('error')
							},
							getLabelInput: function() {
								return document.getElementById('label')
							},
							getDeleteForms: function() {
								return Array.from(document.getElementsByClassName("delete-form"))
							},
						}
						document.addEventListener("DOMContentLoaded",() => setupRegistration({{csrfHeaders}}, "{{contextPath}}", ui));
					//-->
					</script>
				</head>
				<body>
					<div class="container">
						<form class="form-signin" method="post" action="#" onclick="return false">
							<h2 class="form-signin-heading">WebAuthn Registration</h2>
							{{message}}
							<div id="success" class="alert alert-success" role="alert"></div>
							<div id="error" class="alert alert-danger" role="alert"></div>
							<p>
								<input type="text" id="label" name="label" class="form-control" placeholder="Passkey Label" required autofocus>
							</p>
							<button id="register" class="btn btn-lg btn-primary btn-block" type="submit">Register</button>
						</form>
						<table class="table table-striped">
							<thead>
								<tr><th>Label</th><th>Created</th><th>Last Used</th><th>Signature Count</th><th>Delete</th></tr>
							</thead>
							<tbody>
								{{passkeys}}
							</tbody>
						</table>
					</div>
				</body>
			</html>
			""";

	private static final String PASSKEY_ROW_TEMPLATE = """
				<tr>
					<td>{{label}}</td>
					<td>{{created}}</td>
					<td>{{lastUsed}}</td>
					<td>{{signatureCount}}</td>
					<td>
						<form class="delete-form" method="post" action="{{contextPath}}/webauthn/register/{{credentialId}}">
							<input type="hidden" name="method" value="delete">
							<input type="hidden" name="{{csrfParameterName}}" value="{{csrfToken}}">
							<button class="btn btn-sm btn-primary btn-block" type="submit">Delete</button>
						</form>
					</td>
				</tr>
			""";

	private static final String SUCCESS_MESSAGE = """
					<div class="alert alert-success" role="alert">Success!</div>
			""";

	private static final String CSRF_HEADERS = """
			{"{{headerName}}" : "{{headerValue}}"}""";

}
