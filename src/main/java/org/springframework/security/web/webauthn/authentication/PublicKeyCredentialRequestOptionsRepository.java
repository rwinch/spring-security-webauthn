package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;

public interface PublicKeyCredentialRequestOptionsRepository {
	void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialRequestOptions options);

	PublicKeyCredentialRequestOptions load(HttpServletRequest request);
}
