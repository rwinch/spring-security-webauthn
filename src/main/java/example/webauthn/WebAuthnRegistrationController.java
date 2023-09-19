package example.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@Controller
public class WebAuthnRegistrationController {
	@GetMapping("/webauthn/registration")
	String register() {
		return "registration";
	}

	@PostMapping("/webauthn/registration")
	String a(@RequestBody Map<String, Object> body) throws Exception {
		ObjectMapper o = new ObjectMapper();
		o.writeValue(System.out, body);
		return "ok";
	}
}
