package org.springframework.security.web.webauthn.api;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Base64;

public class BufferSourceSerializer extends StdSerializer<BufferSource> {

	private final Base64.Encoder encoder = Base64.getEncoder();

	public BufferSourceSerializer() {
		super(BufferSource.class);
	}

	@Override
	public void serialize(BufferSource bufferSource, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		String base64 = this.encoder.encodeToString(bufferSource.getBytes());
		jgen.writeString(base64);
	}
}
