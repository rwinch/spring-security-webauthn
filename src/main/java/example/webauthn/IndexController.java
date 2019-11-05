package example.webauthn;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author Rob Winch
 */
@Controller
public class IndexController {
	@GetMapping("/")
	String index() {
		return "index";
	}
}
