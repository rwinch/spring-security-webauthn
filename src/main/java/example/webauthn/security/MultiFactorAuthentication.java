package example.webauthn.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

/**
 * @author Rob Winch
 */
public class MultiFactorAuthentication implements Authentication {
	private final Authentication delegate;

	public MultiFactorAuthentication(Authentication delegate) {
		this.delegate = delegate;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return delegate.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return delegate.getCredentials();
	}

	@Override
	public Object getDetails() {
		return delegate.getDetails();
	}

	@Override
	public Object getPrincipal() {
		return delegate.getPrincipal();
	}

	@Override
	public boolean isAuthenticated() {
		return delegate.isAuthenticated();
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated)
			throws IllegalArgumentException {
		delegate.setAuthenticated(isAuthenticated);
	}

	@Override
	public boolean equals(Object another) {
		return delegate.equals(another);
	}

	@Override
	public String toString() {
		return delegate.toString();
	}

	@Override
	public int hashCode() {
		return delegate.hashCode();
	}

	@Override
	public String getName() {
		return delegate.getName();
	}

	@Override
	public boolean implies(Subject subject) {
		return delegate.implies(subject);
	}
}
