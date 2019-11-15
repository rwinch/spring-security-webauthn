package org.springframework.security.web.webauthn;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rob Winch
 */
public class WebAuthnParamsRepository {

	private String registrationParamsAttrName = "registrationParamsAttr";

	private String loginParamsAttrName = "loginParamsAttr";

	public void saveRegistrationParams(HttpServletRequest request, HttpServletResponse response, ServerRegistrationParameters params) {
		request.getSession().setAttribute(this.registrationParamsAttrName, params);
	}

	public ServerRegistrationParameters loadRegistrationParams(HttpServletRequest request) {
		return (ServerRegistrationParameters) request.getSession().getAttribute(this.registrationParamsAttrName);
	}

	public void saveLoginParams(HttpServletRequest request, HttpServletResponse response, ServerLoginParameters params) {
		request.getSession().setAttribute(this.loginParamsAttrName, params);
	}

	public ServerLoginParameters loadLoginParams(HttpServletRequest request) {
		return (ServerLoginParameters) request.getSession().getAttribute(this.loginParamsAttrName);
	}
}
