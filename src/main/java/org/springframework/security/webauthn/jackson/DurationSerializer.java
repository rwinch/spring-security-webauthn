package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.webauthn.api.core.BufferSource;

import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;

public class DurationSerializer extends StdSerializer<Duration> {


	public DurationSerializer() {
		super(Duration.class);
	}

	@Override
	public void serialize(Duration duration, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		jgen.writeNumber(duration.toMillis());
	}
}
