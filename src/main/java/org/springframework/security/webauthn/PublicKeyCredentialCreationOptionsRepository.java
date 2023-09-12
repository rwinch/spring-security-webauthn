package org.springframework.security.webauthn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface PublicKeyCredentialCreationOptionsRepository {
	void save(PublicKeyCredentialCreationOptions options, HttpServletRequest request, HttpServletResponse response);

	PublicKeyCredentialCreationOptions load(HttpServletRequest request);
}
