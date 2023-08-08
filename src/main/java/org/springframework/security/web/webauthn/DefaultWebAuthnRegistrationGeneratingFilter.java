package org.springframework.security.web.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * @author Rob Winch
 */
public class DefaultWebAuthnRegistrationGeneratingFilter extends OncePerRequestFilter {
	private RequestMatcher matches = new AntPathRequestMatcher("/webauthn/register", "GET");

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final WebAuthnManager manager;

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = request -> Collections
			.emptyMap();

	public DefaultWebAuthnRegistrationGeneratingFilter(WebAuthnManager manager) {
		this.manager = manager;
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(
			Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.matches.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		PublicKeyCredentialCreationOptions options = this.manager.createPublicKeyCredentialCreationOptions(authentication);
		request.setAttribute(PublicKeyCredentialCreationOptions.class.getName(), options);
		writeRegistrationPageHtml(request, response);
	}

	private void writeRegistrationPageHtml(HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		PublicKeyCredentialCreationOptions options = (PublicKeyCredentialCreationOptions) request.getAttribute(PublicKeyCredentialCreationOptions.class.getName());

		ObjectMapper objectMapper = new ObjectMapper();
		String objectsJson = objectMapper.writeValueAsString(options);

		response.setContentType("text/html;charset=UTF-8");

		// register:45 Error:NotSupportedError, Message:Only exactly one of 'password', 'federated', and 'publicKey' credential types are currently supported.

		response.getWriter().write("""
				<!DOCTYPE html>
				<html lang=\"en\" xmlns:th=\"https://www.thymeleaf.org\">
				<head>
				    <meta charset=\"utf-8\">
				    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">
				    <meta name=\"description\" content=\"\">
				    <meta name=\"author\" content=\"\">
				    <title>WebAuthn - Registration</title>
				    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">
				    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>
				</head>
				<body>
				<div class=\"container\">
				    <form id=\"register\" class=\"form-signin\" method=\"post\" action=\"""" + request.getContextPath() + """
				/webauthn/register\">
				        <h2 class=\"form-signin-heading\">WebAuthn - Registration</h2>
				        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Register</button>
				        <input type=\"hidden\" id=\"clientDataJSON\" name=\"clientDataJSON\">
				        <input type=\"hidden\" id=\"attestationObject\" name=\"attestationObject\">
				        <input type=\"hidden\" id=\"clientExtensions\" name=\"clientExtensions\">
				        
				"""
				+ renderHiddenInputs(request) +
				"""
				    </form>
				</div>
				    <script
				            src=\"https://code.jquery.com/jquery-3.4.1.js\"
				            integrity=\"sha256-WpOohJOqMqqyKL9FccASB9O0KwACQJpFTUBLTYOVvVU=\"
				            crossorigin=\"anonymous\"></script>
				    <script type=\"text/javascript\">\"use strict\";!function(r){for(var e=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\",t=new Uint8Array(256),n=0;n<e.length;n++)t[e.charCodeAt(n)]=n;r.decodeBase64url=function(r){for(var e=r.length,n=\"=\"===r.charAt(e-2)?2:\"=\"===r.charAt(e-1)?1:0,a=new ArrayBuffer(3*e/4-n),c=new Uint8Array(a),o=0,s=0;s<e;s+=4){var h=t[r.charCodeAt(s)],u=t[r.charCodeAt(s+1)],i=t[r.charCodeAt(s+2)],A=t[r.charCodeAt(s+3)];c[o++]=h<<2|u>>4,c[o++]=(15&u)<<4|i>>2,c[o++]=(3&i)<<6|63&A}return a},r.encodeBase64url=function(r){for(var t=new Uint8Array(r),n=t.length,a=\"\",c=0;c<n;c+=3)a+=e[t[c]>>2],a+=e[(3&t[c])<<4|t[c+1]>>4],a+=e[(15&t[c+1])<<2|t[c+2]>>6],a+=e[63&t[c+2]];switch(n%3){case 1:a=a.substring(0,a.length-2);break;case 2:a=a.substring(0,a.length-1)}return a}}(\"undefined\"==typeof exports?this.base64url={}:exports);</script>
				    <script type=\"text/javascript\">
				        if (!window.PublicKeyCredential) { /* Client not capable. Handle error. */ }
				
				        function register() {
				            const publicKey = """ + objectsJson +

				"""

				            publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), c => c.charCodeAt(0))
				            publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), c => c.charCodeAt(0))
				            return navigator.credentials.create({ publicKey })
				                .then(function (newCredentialInfo) {
				                    console.log('Created credentials');
				                    console.log(newCredentialInfo);
				                    $('#clientDataJSON').val(base64url.encodeBase64url(newCredentialInfo.response.clientDataJSON));
				                    $('#attestationObject').val(base64url.encodeBase64url(newCredentialInfo.response.attestationObject));
				                    $('#clientExtensions').val(JSON.stringify(newCredentialInfo.getClientExtensionResults()));
				                    console.log(\"Updated the hidden inputs\");
				                }).catch(function (e) {
				                    console.error(\"Error:%s, Message:%s\", e.name, e.message);
				                });
				        }
				        $(document).ready(function() {
				            $(\"#register\").submit(function(e) {
				                var f = this;
				                register().then(r => f.submit());
				                return false;
				            });
				        });
				    </script>
				</body></html>
""");
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"").append(input.getKey()).append("\" type=\"hidden\" value=\"").append(input.getValue()).append("\" />\n");
		}
		return sb.toString();
	}
}
