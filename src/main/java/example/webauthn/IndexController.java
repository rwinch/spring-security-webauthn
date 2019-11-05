package example.webauthn;

import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;
import java.util.Map;

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
