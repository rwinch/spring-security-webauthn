package org.springframework.security.web.webauthn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;

public class HttpSessionPublicKeyCredentialCreationOptionsRepository implements PublicKeyCredentialCreationOptionsRepository {
	private String attrName = PublicKeyCredentialCreationOptions.class.getName();

	@Override
	public void save(PublicKeyCredentialCreationOptions options, HttpServletRequest request, HttpServletResponse response) {
		request.getSession().setAttribute(this.attrName, options);
	}

	@Override
	public PublicKeyCredentialCreationOptions load(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		return session == null ? null : (PublicKeyCredentialCreationOptions) session.getAttribute(this.attrName);
	}
}
