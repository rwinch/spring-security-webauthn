package org.springframework.security.web.webauthn.api;

import java.util.List;

public class PublicKeyCredentialDescriptor {
	private final String type;

	private final BufferSource id;

	private final List<String> transports;

	public PublicKeyCredentialDescriptor(String type, BufferSource id, List<String> transports) {
		this.type = type;
		this.id = id;
		this.transports = transports;
	}

	public String getType() {
		return this.type;
	}

	public BufferSource getId() {
		return this.id;
	}

	public List<String> getTransports() {
		return this.transports;
	}
}
