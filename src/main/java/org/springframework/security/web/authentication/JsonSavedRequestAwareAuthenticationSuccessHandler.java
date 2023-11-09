package org.springframework.security.web.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.Assert;

import java.io.IOException;

public class JsonSavedRequestAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	private GenericHttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();

	private RequestCache requestCache = new HttpSessionRequestCache();

	public void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		final SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		final String redirectUrl = (savedRequest != null) ? savedRequest.getRedirectUrl() : request.getContextPath() + "/";
		this.requestCache.removeRequest(request, response);
		this.converter.write(new AuthenticationSuccess(redirectUrl), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
	}

	private static class AuthenticationSuccess {
		private final String redirectUrl;

		private AuthenticationSuccess(String redirectUrl) {
			this.redirectUrl = redirectUrl;
		}

		public String getRedirectUrl() {
			return this.redirectUrl;
		}

		public boolean isAuthenticated() {
			return true;
		}
	}
}
