package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.webauthn.management.UserCredential;
import org.springframework.security.webauthn.management.UserCredentialRepository;
import org.springframework.util.MimeType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class DefaultRegistrationPageGeneratingFilter extends OncePerRequestFilter {
  private RequestMatcher matcher = AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/webauthn/register");
	private final PublicKeyCredentialUserEntityRepository userEntityRepository;

	private final UserCredentialRepository userCredentials;

	public DefaultRegistrationPageGeneratingFilter(PublicKeyCredentialUserEntityRepository userEntityRepository, UserCredentialRepository userCredentials) {
		this.userEntityRepository = userEntityRepository;
		this.userCredentials = userCredentials;
	}

	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
      if (!this.matcher.matches(request)) {
        filterChain.doFilter(request, response);
        return;
      }
		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		String csrfDataAttr = "data-csrf-token=\""+csrfToken.getToken()+"\" data-csrf-header-name=\""+csrfToken.getHeaderName()+"\"";
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write("""
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>WebAuthn Registration</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
    <script src="https://unpkg.com/@simplewebauthn/browser@8.3.1/dist/bundle/index.umd.min.js"></script>
    <script type="text/javascript" id="registration-script" """
	+ csrfDataAttr +
	"""
    >
      <!--
      document.addEventListener("DOMContentLoaded", function(event) {
        setup()
      });
      function setVisibility(elmt, value) {
        elmt.style.display = value ? 'block' : 'none'
      }
      function setup() {
          const config = document.getElementById('registration-script').dataset
          const csrfToken = config.csrfToken
          const csrfHeaderName = config.csrfHeaderName
          const { startRegistration } = SimpleWebAuthnBrowser;

          // <button>
          const elemBegin = document.getElementById('register');
          // <span>/<p>/etc...
          const elemSuccess = document.getElementById('success');
          // <span>/<p>/etc...
          const elemError = document.getElementById('error');


          setVisibility(elemSuccess, false)
          setVisibility(elemError, false)

          // Start registration when the user clicks a button
          elemBegin.addEventListener('click', async () => {
            // Reset success/error messages
            setVisibility(elemSuccess, false)
            setVisibility(elemError, false)
            elemSuccess.innerHTML = '';
            elemError.innerHTML = '';

            // GET registration options from the endpoint that calls
            // @simplewebauthn/server -> generateRegistrationOptions()
            const resp = await fetch('/webauthn/register/options');

            let attResp;
            try {
              // Pass the options to the authenticator and wait for a response
              attResp = await startRegistration(await resp.json());
            } catch (error) {
              // FIXME: For error handling see https://www.w3.org/TR/webauthn-3/#sctn-op-make-cred
              // Some basic error handling
              setVisibility(elemError, true)
              if (error.name === 'InvalidStateError') {
                elemError.innerText = 'Error: Authenticator was probably already registered by user';
              } else {
                elemError.innerText = error;
              }

              throw error;
            }

            // POST the response to the endpoint that calls
            // @simplewebauthn/server -> verifyRegistrationResponse()
            const verificationResp = await fetch('/webauthn/register', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                [csrfHeaderName]: csrfToken,
              },
              body: JSON.stringify(attResp),
            });

            // Wait for the results of verification
            const verificationJSON = await verificationResp.json();

            // Show UI appropriate for the `verified` status
            if (verificationJSON && verificationJSON.verified) {
              setVisibility(elemSuccess, true)
              elemSuccess.innerHTML = 'Success!';
            } else {
              setVisibility(elemError, true)
              elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
                verificationJSON,
              )}</pre>`;
            }
          });
      }
      //-->
    </script>
</head>
<body>
    <div class="container">
      <form class="form-signin" method="post" action="#" onclick="return false">
          <h2 class="form-signin-heading">WebAuthn Registration</h2>
          <div id="success" class="alert alert-success" role="alert"></div>
          <div id="error" class="alert alert-success" role="alert"></div>
        <button id="register" class="btn btn-lg btn-primary btn-block" type="submit">Register</button>
      </form>
      """
		+ credentials(request.getRemoteUser()) +
"""
    </div>
</body>
</html>
				""");
	}

	private String credentials(String username) {
		PublicKeyCredentialUserEntity userEntity = this.userEntityRepository.findByUsername(username);List<UserCredential> credentials = userEntity == null ? Collections.emptyList() : this.userCredentials.findByUserId(userEntity.getId());

		String html = "<table>";
		for (UserCredential credential : credentials) {
			html += "<tr><td>"+credential.getCredentialId()+"</td></tr>";
		}
		return html;
	}
}
