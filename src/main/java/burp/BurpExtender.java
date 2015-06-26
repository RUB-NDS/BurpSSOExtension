/**
 * BurpSSOExtension - An extension for BurpSuite that highlights SSO messages.
 * Copyright (C) 2015/ Christian Mainka
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package burp;

import de.rub.nds.burp.sso.HttpMarker;
import de.rub.nds.burp.sso.editor.SamlRequestEditor;
import de.rub.nds.burp.sso.editor.SamlResponseEditor;

public class BurpExtender implements IBurpExtender {

	private static final String EXTENSION_NAME = "Burp's SSO Extension v1.0";

	IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(
		IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(EXTENSION_NAME);
		final HttpMarker httpMarker = new HttpMarker(callbacks);
		callbacks.registerHttpListener(httpMarker);
		callbacks.registerMessageEditorTabFactory(new SamlResponseEditor(callbacks));
		callbacks.registerMessageEditorTabFactory(new SamlRequestEditor(callbacks));
	}
}
