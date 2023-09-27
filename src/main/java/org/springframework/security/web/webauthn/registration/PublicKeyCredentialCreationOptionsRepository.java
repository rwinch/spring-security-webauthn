package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;

public interface PublicKeyCredentialCreationOptionsRepository {
	void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialCreationOptions options);

	PublicKeyCredentialCreationOptions load(HttpServletRequest request);
}
