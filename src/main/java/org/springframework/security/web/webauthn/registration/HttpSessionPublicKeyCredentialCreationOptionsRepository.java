package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;

public class HttpSessionPublicKeyCredentialCreationOptionsRepository implements PublicKeyCredentialCreationOptionsRepository {
	private String attrName = PublicKeyCredentialCreationOptions.class.getName();
	@Override
	public void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialCreationOptions options) {
		request.getSession().setAttribute(this.attrName, options);
	}

	public PublicKeyCredentialCreationOptions load(HttpServletRequest request) {
		return (PublicKeyCredentialCreationOptions) request.getSession().getAttribute(this.attrName);
	}
}
