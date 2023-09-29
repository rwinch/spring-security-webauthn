package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;

public class HttpSessionPublicKeyCredentialRequestOptionsRepository implements  PublicKeyCredentialRequestOptionsRepository{
	private String attrName = PublicKeyCredentialRequestOptionsRepository.class.getName();

	@Override
	public void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialRequestOptions options) {
		request.getSession().setAttribute(this.attrName, options);
	}

	@Override
	public PublicKeyCredentialRequestOptions load(HttpServletRequest request) {
		return (PublicKeyCredentialRequestOptions) request.getSession().getAttribute(this.attrName);
	}
}
