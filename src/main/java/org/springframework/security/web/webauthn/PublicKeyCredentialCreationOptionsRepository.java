package org.springframework.security.web.webauthn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;

public interface PublicKeyCredentialCreationOptionsRepository {
	void save(PublicKeyCredentialCreationOptions options, HttpServletRequest request, HttpServletResponse response);

	PublicKeyCredentialCreationOptions load(HttpServletRequest request);
}
