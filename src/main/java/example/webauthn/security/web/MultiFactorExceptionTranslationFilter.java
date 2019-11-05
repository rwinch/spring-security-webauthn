package example.webauthn.security.web;

import example.webauthn.security.MultiFactorAuthenticationRequiredException;
import example.webauthn.security.MultiFactorRegistrationRequiredException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
