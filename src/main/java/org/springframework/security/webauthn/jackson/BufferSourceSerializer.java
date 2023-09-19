package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.core.BufferSource;

import java.io.IOException;
import java.util.Base64;

public class BufferSourceSerializer extends StdSerializer<BufferSource> {


	public BufferSourceSerializer() {
		super(BufferSource.class);
	}

	@Override
	public void serialize(BufferSource bufferSource, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeString(bufferSource.getBytesAsBase64());
	}
}
