package org.springframework.security.web.webauthn.api;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

public class COSEAlgorithmIdentifierSerializer extends StdSerializer<COSEAlgorithmIdentifier> {
	public COSEAlgorithmIdentifierSerializer() {
		super(COSEAlgorithmIdentifier.class);
	}

	@Override
	public void serialize(COSEAlgorithmIdentifier identifier, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeNumber(identifier.getRegistryId());
	}
}
