package org.springframework.security.web.webauthn;

import example.webauthn.security.MultiFactorAuthenticationRequiredException;
import example.webauthn.security.MultiFactorRegistrationRequiredException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Rob Winch
 */
public class MultiFactorExceptionTranslationFilter extends OncePerRequestFilter {
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			filterChain.doFilter(request, response);
		} catch (MultiFactorAuthenticationRequiredException multi) {
			this.requestCache.saveRequest(request, response);
			this.redirectStrategy.sendRedirect(request, response, "/login/webauthn");
		} catch (MultiFactorRegistrationRequiredException multi) {
			this.requestCache.saveRequest(request, response);
			this.redirectStrategy.sendRedirect(request, response, "/webauthn/register");
		}
	}
}
