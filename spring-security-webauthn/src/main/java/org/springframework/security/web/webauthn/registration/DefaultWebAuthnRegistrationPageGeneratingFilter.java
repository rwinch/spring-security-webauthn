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
import org.springframework.security.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.webauthn.management.CredentialRecord;
import org.springframework.security.webauthn.management.UserCredentialRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A {@link jakarta.servlet.Filter} that renders a default WebAuthn registration page.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class DefaultWebAuthnRegistrationPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/webauthn/register");

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	/**
	 * Creates a new instance.
	 *
	 * @param userEntities the {@link PublicKeyCredentialUserEntity}
	 * @param userCredentials
	 */
	public DefaultWebAuthnRegistrationPageGeneratingFilter(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials) {
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
		Map<String, Object> context = new HashMap<>();
		context.put("contextPath", request.getContextPath());
		context.put("csrfToken", csrfToken.getToken());
		context.put("csrfParameterName", csrfToken.getParameterName());
		context.put("csrfHeaderName", csrfToken.getHeaderName());
		context.put("csrfHeaders", createCsrfHeaders(csrfToken));
		context.put("message", success ? SUCCESS_MESSAGE : "");
		context.put("passkeys", passkeyRows(request.getRemoteUser(), context));
		response.getWriter().write(processTemplate(HTML_TEMPLATE, context));
	}

	private String passkeyRows(String username, Map<String,Object> baseContext) {
		PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(username);
		List<CredentialRecord> credentials = userEntity == null ? Collections.emptyList() : this.userCredentials.findByUserId(userEntity.getId());
		if (credentials.isEmpty()) {
			return """
				<tr><td colspan="5">No Passkeys</td></tr>
				""";
		}
		String html = "";
		for (CredentialRecord credential : credentials) {
			Map<String, Object> context = new HashMap<>(baseContext);
			context.put("label", HtmlUtils.htmlEscape(credential.getLabel()));
			context.put("created", credential.getCreated());
			context.put("lastUsed", credential.getLastUsed());
			context.put("signatureCount", credential.getSignatureCount());
			context.put("credentialId", credential.getCredentialId().toBase64UrlString());
			html += processTemplate(PASSKEY_ROW_TEMPLATE, context);
		}
		return html;
	}

	private String processTemplate(String template, Map<String,Object> context) {
		for (Map.Entry<String, Object> entry : context.entrySet()) {
			String pattern = Pattern.quote("${" + entry.getKey() + "}");
			String value = String.valueOf(entry.getValue());
			template = template.replaceAll(pattern, value);
		}
		return template;
	}

	private String createCsrfHeaders(CsrfToken csrfToken) {
		Map<String, Object> headerContext = Map.of("headerName", csrfToken.getHeaderName(), "headerValue",
				csrfToken.getToken());
		return processTemplate(CSRF_HEADERS, headerContext);
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
				<script type="text/javascript" src="${contextPath}/login/webauthn.js"></script>
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
					document.addEventListener("DOMContentLoaded",() => setupRegistration(${csrfHeaders}, "${contextPath}", ui));
				//-->
				</script>
			</head>
			<body>
				<div class="container">
					<form class="form-signin" method="post" action="#" onclick="return false">
						<h2 class="form-signin-heading">WebAuthn Registration</h2>
						${message}
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
							${passkeys}
						</tbody>
					</table>
				</div>
			</body>
		</html>
""";

	private static final String PASSKEY_ROW_TEMPLATE = """
		<tr>
			<td>${label}</td>
			<td>${created}</td>
			<td>${lastUsed}</td>
			<td>${signatureCount}</td>
			<td>
				<form class="delete-form" method="post" action="${contextPath}/webauthn/register/${credentialId}">
					<input type="hidden" name="method" value="delete">
					<input type="hidden" name="${csrfParameterName}" value="${csrfToken}">
					<button class="btn btn-sm btn-primary btn-block" type="submit">Delete</button>
				</form>
			</td>
		</tr>
	""";

	private static final String SUCCESS_MESSAGE = """
 		<div class="alert alert-success" role="alert">Success!</div>
	""";

	private static final String CSRF_HEADERS = """
			{"${headerName}" : "${headerValue}"}""";

}
