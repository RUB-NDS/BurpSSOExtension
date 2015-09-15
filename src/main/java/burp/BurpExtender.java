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
import de.rub.nds.burp.espresso.scanner.ScanAndMarkSSO;
import de.rub.nds.burp.espresso.editor.JSONEditor;
import de.rub.nds.burp.espresso.editor.JWTEditor;
import de.rub.nds.burp.espresso.editor.SAMLEditor;
import de.rub.nds.burp.utilities.Logging;
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
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    
    /**
     * Register all new functions like for the internals and GUI.
     * Registered are Editors, a Tab and HttpListners
     * @param callbacks Provided by the Burp Suite api.
     */
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        //set extension name - ExPReSSO - Extension for Processing and Recognition of Single Sign-On
        callbacks.setExtensionName(EXTENSION_NAME);
        
        //optain streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        //register a new Tab
        tab = new UITab(callbacks);
        
        //integrate the extension of Christian Mainka
        final ScanAndMarkSSO scanAndMark = new ScanAndMarkSSO(callbacks);
	callbacks.registerHttpListener(scanAndMark);
        callbacks.registerMessageEditorTabFactory(new SAMLEditor(callbacks));
        
        //New Editors
        callbacks.registerMessageEditorTabFactory(new JSONEditor(callbacks));
        callbacks.registerMessageEditorTabFactory(new JWTEditor(callbacks));
        callbacks.registerExtensionStateListener(this);
        
        //Start logging
        Logging.getInstance().log(getClass().getName(), "All functions registered.", false);
    }
    /**
     * Print a notification on the standard output when extension is unloaded.
     */

    @Override
    public void extensionUnloaded() {
        Logging.getInstance().log(getClass().getName(), "Extension is now unloaded.", false);
    }
 
}
