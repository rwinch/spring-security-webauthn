package org.springframework.security.webauthn.management;

// FIXME: Consider placing in a place that is reusable
public enum OptionalBoolean {
	TRUE(true),
	FALSE(false),
	UNKNOWN(null);

	private final Boolean value;

	OptionalBoolean(Boolean value) {
		this.value = value;
	}

	public Boolean getValue() {
		return this.value;
	}

	public static OptionalBoolean fromBoolean(Boolean value) {
		if (value == null) {
			return UNKNOWN;
		}
		return value ? TRUE : FALSE;
	}
}
