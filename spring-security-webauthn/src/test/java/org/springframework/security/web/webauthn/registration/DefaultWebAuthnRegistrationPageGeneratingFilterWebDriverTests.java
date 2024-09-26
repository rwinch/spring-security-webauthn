/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.DispatcherType;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.webauthn.management.UserCredentialRepository;
import org.springframework.security.webauthn.management.Webauthn4JRelyingPartyOperations;

import java.lang.reflect.Constructor;
import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * https://www.selenium.dev/documentation/webdriver/interactions/virtual_authenticator/
 * https://github.com/SeleniumHQ/seleniumhq.github.io/blob/trunk/examples/java/src/test/java/dev/selenium/interactions/VirtualAuthenticatorTest.java#L100-L103
 */
@ExtendWith(MockitoExtension.class)
public class DefaultWebAuthnRegistrationPageGeneratingFilterWebDriverTests {

	private static ChromeDriverService driverService;

	@Mock
	private PublicKeyCredentialUserEntityRepository userEntities;

	@Mock
	private UserCredentialRepository userCredentials;

	private RemoteWebDriver driver;

	private Server server;

	private String baseUrl;

	@BeforeAll
	static void startChromeDriverService() throws Exception {
		driverService = new ChromeDriverService.Builder()
				.usingAnyFreePort()
				.build();
		driverService.start();
	}

	@AfterAll
	static void stopChromeDriverService() {
		driverService.stop();
	}

	@BeforeEach
	void setupDriver() {
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless=new");
		this.driver = new RemoteWebDriver(driverService.getUrl(), options);
	}

	@BeforeEach
	void setupServer() throws Exception {
		ServletContextHandler servlet = new ServletContextHandler(ServletContextHandler.SESSIONS);
		DefaultWebAuthnRegistrationPageGeneratingFilter filter = new DefaultWebAuthnRegistrationPageGeneratingFilter(this.userEntities, this.userCredentials);

		Constructor<DefaultResourcesFilter> constructor = DefaultResourcesFilter.class.getDeclaredConstructor(RequestMatcher.class, ClassPathResource.class, MediaType.class);
		constructor.setAccessible(true);
		ClassPathResource webauthn = new ClassPathResource("org/springframework/security/spring-security-webauthn.js");
		AntPathRequestMatcher matcher = antMatcher(GET, "/login/webauthn.js");
		DefaultResourcesFilter resourcesFilter =
				constructor.newInstance(matcher, webauthn, MediaType.parseMediaType("text/javascript"));

		servlet.addFilter(new FilterHolder(new CsrfFilter(new HttpSessionCsrfTokenRepository())),"/*", EnumSet.allOf(DispatcherType.class));
		servlet.addFilter(new FilterHolder(resourcesFilter),"/*", EnumSet.allOf(DispatcherType.class));
		servlet.addFilter(new FilterHolder(filter),"/*", EnumSet.allOf(DispatcherType.class));

		this.server = new Server(0);
		this.server.setHandler(servlet);
		this.server.start();
		this.baseUrl = "http://localhost:"+ ((ServerConnector) this.server.getConnectors()[0]).getLocalPort();
	}

	@AfterEach
	void stopServer() throws Exception {
		this.server.stop();
	}

	@AfterEach
	void cleanupDriver() {
		this.driver.quit();
	}

	@Test
	void registerWhenPasskeyLabelEmptyThenRequired() throws Exception {
		VirtualAuthenticatorOptions authenticatorOptions = createVirtualAuthenticatorOptions();
		this.driver.addVirtualAuthenticator(authenticatorOptions);

		this.driver.get(this.baseUrl + "/webauthn/register");
		this.driver.findElement(By.id("register")).click();
		assertThat(this.driver.findElement(By.id("error")).getText()).isEqualTo("Error: Passkey Label is required");
	}

	@Test
	void registerWhenThenSuccess() throws Exception {
		VirtualAuthenticatorOptions authenticatorOptions = createVirtualAuthenticatorOptions();
		VirtualAuthenticator virtualAuthenticator = this.driver.addVirtualAuthenticator(authenticatorOptions);
		virtualAuthenticator.setUserVerified(true);

		this.driver.get(this.baseUrl + "/webauthn/register");
		this.driver.findElement(By.id("label")).sendKeys("Virtual autheneticator");
		this.driver.findElement(By.id("register")).click();
		this.driver.getPageSource();
	}

	private static VirtualAuthenticatorOptions createVirtualAuthenticatorOptions() {
		return new VirtualAuthenticatorOptions()
				.setIsUserVerified(true)
				.setHasUserVerification(true)
				.setIsUserConsenting(true)
				.setTransport(VirtualAuthenticatorOptions.Transport.INTERNAL)
				.setProtocol(VirtualAuthenticatorOptions.Protocol.CTAP2)
				.setHasResidentKey(false);
	}
}
