import { setup } from "./webauthn-login.js";
// Make "setup" available in the window domain, so it can be run with "setupLogin()"
window.setupLogin = setup;
