package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonInputMessage;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.authentication.WebAuthnAuthenticationRequestToken;
import org.springframework.security.webauthn.management.AuthenticationRequest;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.StringJoiner;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public class WebAuthnAuthenticationFilter extends AbstractAuthenticationProcessingFilter  {
	private GenericHttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	public WebAuthnAuthenticationFilter() {
		super(antMatcher(HttpMethod.POST, "/login/webauthn"));
		setSecurityContextRepository(new HttpSessionSecurityContextRepository());
	}
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		ServletServerHttpRequest httpRequest = new ServletServerHttpRequest(request);
		SyntheticParameterizedType type = new SyntheticParameterizedType(PublicKeyCredential.class, new Type[]{AuthenticatorAssertionResponse.class});
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = (PublicKeyCredential<AuthenticatorAssertionResponse>) this.converter.read(type, WebAuthnAuthenticationFilter.class, httpRequest);
		PublicKeyCredentialRequestOptions requestOptions = this.requestOptionsRepository.load(request);
		AuthenticationRequest authenticationRequest = new AuthenticationRequest(requestOptions, publicKeyCredential);
		WebAuthnAuthenticationRequestToken token = new WebAuthnAuthenticationRequestToken(authenticationRequest);
		return getAuthenticationManager().authenticate(token);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		response.getWriter().write("{ \"verified\" : \"true\" }");
		super.successfulAuthentication(request, response, chain, authResult);
	}

	private static final class SyntheticParameterizedType implements ParameterizedType, Serializable {

		private final Type rawType;

		private final Type[] typeArguments;

		public SyntheticParameterizedType(Type rawType, Type[] typeArguments) {
			this.rawType = rawType;
			this.typeArguments = typeArguments;
		}

		@Override
		public String getTypeName() {
			String typeName = this.rawType.getTypeName();
			if (this.typeArguments.length > 0) {
				StringJoiner stringJoiner = new StringJoiner(", ", "<", ">");
				for (Type argument : this.typeArguments) {
					stringJoiner.add(argument.getTypeName());
				}
				return typeName + stringJoiner;
			}
			return typeName;
		}

		@Override
		@Nullable
		public Type getOwnerType() {
			return null;
		}

		@Override
		public Type getRawType() {
			return this.rawType;
		}

		@Override
		public Type[] getActualTypeArguments() {
			return this.typeArguments;
		}

		@Override
		public boolean equals(@Nullable Object other) {
			return (this == other || (other instanceof ParameterizedType that &&
					that.getOwnerType() == null && this.rawType.equals(that.getRawType()) &&
					Arrays.equals(this.typeArguments, that.getActualTypeArguments())));
		}

		@Override
		public int hashCode() {
			return (this.rawType.hashCode() * 31 + Arrays.hashCode(this.typeArguments));
		}

		@Override
		public String toString() {
			return getTypeName();
		}
	}
}
