/**
 * EsPReSSO - Extension for Processing and Recognition of Single Sign-On Protocols.
 * Copyright (C) 2015/ Tim Guenther and Christian Mainka
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

import de.rub.nds.burp.espresso.gui.UITab;
import de.rub.nds.burp.espresso.scanner.SSOScanner;
import de.rub.nds.burp.espresso.HttpMarker;
import de.rub.nds.burp.espresso.editor.SamlRequestEditor;
import de.rub.nds.burp.espresso.editor.SamlResponseEditor;
import java.io.PrintWriter;


/**
 * The first class called by Burp Suite.
 * This is the starting class for all other functionalities.
 * @author Tim Guenther
 * @version 1.0
 */

public class BurpExtender implements IBurpExtender, IExtensionStateListener{
    /**
     * {@value #EXTENSION_NAME}
     */
    public static final String EXTENSION_NAME = "EsPReSSO";
    
    private UITab tab;
    private PrintWriter stdout;
    
    /**
     * Register all new functions like for the internals and GUI.
     * Registered are Editors, a Tab and HttpListners
     * @param callbacks Provided by the Burp Suite api.
     */
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        //set extension name - ExPReSSO - Extension for Processing and Recognition of Single Sign-On
        callbacks.setExtensionName(EXTENSION_NAME);
        
        //optain output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        //register a new Tab
        tab = new UITab(callbacks);
        
        //
        final SSOScanner ssoScanner = new SSOScanner(callbacks, tab);
        callbacks.registerHttpListener(ssoScanner);
        
        //integrate the extension of Christian Mainka
        final HttpMarker httpMarker = new HttpMarker(callbacks);
	callbacks.registerHttpListener(httpMarker);
	callbacks.registerMessageEditorTabFactory(new SamlResponseEditor(callbacks));
	callbacks.registerMessageEditorTabFactory(new SamlRequestEditor(callbacks));
    }
    /**
     * Print a notification on the standard output when extension is unloaded.
     */

    @Override
    public void extensionUnloaded() {
        stdout.println("Extension is now unloaded.");
    }
 
}
