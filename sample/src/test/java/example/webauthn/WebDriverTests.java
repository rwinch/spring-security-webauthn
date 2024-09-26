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

package example.webauthn;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.HasCdp;
import org.openqa.selenium.devtools.HasDevTools;
import org.openqa.selenium.remote.Augmenter;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebDriverTests {

	@LocalServerPort
	private int port;

	private RemoteWebDriver driver;

	private static ChromeDriverService driverService;

	private String baseUrl;

	private String virtualAuthenticatorId;

	@BeforeAll
	static void startChromeDriverService() throws Exception {
		driverService = new ChromeDriverService.Builder().usingAnyFreePort().build();
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
		var baseDriver = new RemoteWebDriver(driverService.getUrl(), options);
		// Enable dev tools
		this.driver = (RemoteWebDriver) new Augmenter().augment(baseDriver);
		this.driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(1));
		this.baseUrl = "https://example.localhost:" + this.port;
	}

	@Test
	@Order(1)
	void loginNoAuthenticator() {
		this.driver.get(this.baseUrl);
		this.driver.findElement(new By.ById("passkey-signin")).click();
		//@formatter:off
		Awaitility.await()
				.atMost(Duration.ofSeconds(1))
				.untilAsserted(() -> {
					assertThat(this.driver.getCurrentUrl()).endsWith("/login?error");
				});
		//@formatter:on
	}

	@Test
	@Order(2)
	void passkeyLabelRequired() {
		login();

		this.driver.get(this.baseUrl + "/webauthn/register");

		this.driver.findElement(new By.ById("register")).click();
		WebElement errorPopup = this.driver.findElement(new By.ById("error"));

		assertThat(errorPopup.isDisplayed()).isTrue();
		assertThat(errorPopup.getText()).isEqualTo("Error: Passkey Label is required");
	}

	@Test
	@Order(3)
	void registerAuthenticatorRejects() {
		createVirtualAuthenticator(false);
		login();
		this.driver.get(this.baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("label")).sendKeys("Virtual authenticator");
		this.driver.findElement(new By.ById("register")).click();

		//@formatter:off
		Awaitility.await()
				.atMost(Duration.ofSeconds(2))
				.untilAsserted(() -> {
					var errorPopup = this.driver.findElement(new By.ById("error"));
					assertThat(errorPopup.isDisplayed())
							.withFailMessage(() -> "Error popup was not displayed. Full page source:\n\n" + this.driver.getPageSource())
							.isTrue();

					assertThat(errorPopup.getText()).startsWith("Registration failed. Call to navigator.credentials.create failed: The operation either timed out or was not allowed.");
				});
		//@formatter:on;
	}

	@Test
	@Order(4)
	void endToEnd() {
		// Setup
		createVirtualAuthenticator(true);
		login();

		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		// 1. Register authenticator
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		this.driver.get(this.baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("label")).sendKeys("Virtual authenticator");
		this.driver.findElement(new By.ById("register")).click();

		//@formatter:off
		Awaitility.await()
				.atMost(Duration.ofSeconds(2))
				.untilAsserted(() -> {
					var successPopup = this.driver.findElement(new By.ById("success"));
					assertThat(successPopup.isDisplayed())
							.withFailMessage(() -> "Success popup was not displayed. Full page source:\n\n" + this.driver.getPageSource())
							.isTrue();
				});
		//@formatter:on;

		var passkeyRows = this.driver.findElements(new By.ByCssSelector("table > tbody > tr"));
		assertThat(passkeyRows).hasSize(1)
			.first()
			.extracting(row -> row.findElement(new By.ByCssSelector("td:first-child")))
			.extracting(WebElement::getText)
			.isEqualTo("Virtual authenticator");

		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		// 2. Logout
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		logout();

		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		// 3. Login with authenticator
		// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		this.driver.get(this.baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("passkey-signin")).click();
		Awaitility.await()
			.atMost(Duration.ofSeconds(1))
			.untilAsserted(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/webauthn/register?continue"));
	}

	private void login() {
		this.driver.get(this.baseUrl);
		this.driver.findElement(new By.ById("username")).sendKeys("user");
		this.driver.findElement(new By.ById("password")).sendKeys("password");
		this.driver.findElement(new By.ByCssSelector("form > button[type=\"submit\"]")).click();
	}

	private void logout() {
		this.driver.get(this.baseUrl + "/logout");
		this.driver.findElement(new By.ByCssSelector("button")).click();
		//@formatter:off
		Awaitility.await()
				.atMost(Duration.ofSeconds(1))
				.untilAsserted(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/login?logout"));
		//@formatter:on
	}

	/**
	 * Add a virtual authenticator.
	 * <p>
	 * Note that Selenium docs for {@link HasCdp} strongly encourage to use
	 * {@link HasDevTools} instead. However, devtools require more dependencies and
	 * boilerplate, notably to sync the Devtools-CDP version with the current browser
	 * version, whereas CDP runs out of the box.
	 * <p>
	 * @param userIsVerified whether the authenticator simulates user verification.
	 * Setting it to false will make the ceremonies fail.
	 * @see <a href=
	 * "https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/">https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/</a>
	 */
	private void createVirtualAuthenticator(boolean userIsVerified) {
		//
		var cdpDriver = (HasCdp) this.driver;
		cdpDriver.executeCdpCommand("WebAuthn.enable", Map.of("enableUI", false));
		// this.driver.addVirtualAuthenticator(createVirtualAuthenticatorOptions());
		//@formatter:off
		var commandResult = cdpDriver.executeCdpCommand("WebAuthn.addVirtualAuthenticator",
				Map.of(
						"options",
						Map.of(
								"protocol", "ctap2",
								"transport", "usb",
								"hasUserVerification", true,
								"hasResidentKey", true,
								"isUserVerified", userIsVerified,
								"automaticPresenceSimulation", true
						)
				));
		//@formatter:on
		this.virtualAuthenticatorId = commandResult.get("authenticatorId").toString();
	}

}
