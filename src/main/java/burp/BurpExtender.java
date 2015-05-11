/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import de.threecurity.burp.sso.HttpMarker;

public class BurpExtender implements IBurpExtender {
	private static final String EXTENSION_NAME = "Burp's SSO Extension v0.1";

	IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(
		IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(EXTENSION_NAME);
		final HttpMarker httpMarker = new HttpMarker(callbacks);
		callbacks.registerHttpListener(httpMarker);
	}
}
