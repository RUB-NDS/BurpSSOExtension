/**
 * EsPReSSO - Extension for Processing and Recognition of Single Sign-On Protocols.
 * Copyright (C) 2015 Tim Guenther and Christian Mainka
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
import de.rub.nds.burp.espresso.editor.saml.SAMLEditor;
import de.rub.nds.burp.espresso.intruder.dtd.DTDPayloadFactory;
import de.rub.nds.burp.espresso.intruder.xsw.XSWPayloadFactory;
import de.rub.nds.burp.utilities.Logging;
import java.io.PrintWriter;
import java.time.LocalTime;


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
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    
    /**
     * Register all new functions like for the internals and GUI.
     * Registered are Editors, a Tab and a HttpListner
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        //set extension name - ExPReSSO - Extension for Processing and Recognition of Single Sign-On
        callbacks.setExtensionName(EXTENSION_NAME);
        
        //optain streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        stdout.println("+-----------------------------------------------------------------------+");
        stdout.println("| EsPReSSO - Extension for Processing and Recognition of Single Sign-on |");
        stdout.println("|                      Started @ "+time+"                               |");
        stdout.println("+-----------------------------------------------------------------------+");
        
        //register a new Tab
        tab = new UITab(callbacks);
        Logging.getInstance().log(getClass(), "Tab registered.", Logging.INFO);
        
        //integrate the extension of Christian Mainka
        final ScanAndMarkSSO scanAndMark = new ScanAndMarkSSO(callbacks);
	callbacks.registerHttpListener(scanAndMark);
        Logging.getInstance().log(getClass(), "Scanner registered.", Logging.INFO);
        callbacks.registerMessageEditorTabFactory(new SAMLEditor(callbacks));
        Logging.getInstance().log(getClass(), "SAML editor registered.", Logging.INFO);
        
        //New Editors
        callbacks.registerMessageEditorTabFactory(new JSONEditor(callbacks));
        Logging.getInstance().log(getClass(), "JSON editor registered.", Logging.INFO);
        callbacks.registerMessageEditorTabFactory(new JWTEditor(callbacks));
        Logging.getInstance().log(getClass(), "JWT editor registered.", Logging.INFO);
        callbacks.registerExtensionStateListener(this);
        Logging.getInstance().log(getClass(), "ExtensionStateListener registered", Logging.INFO);
        
        //register Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(new DTDPayloadFactory(callbacks));
        callbacks.registerIntruderPayloadGeneratorFactory(new XSWPayloadFactory(callbacks));
        
        //Start logging
        Logging.getInstance().log(getClass(), "Init. complete.", Logging.INFO);
    }
    
    /**
     * Print a notification on the standard output when extension is unloaded.
     */
    @Override
    public void extensionUnloaded() {
        Logging.getInstance().log(getClass(), "Extension is now unloaded.", Logging.INFO);
        stdout.println("");
        stderr.println("");
    }
    
    /**
     * Get a {@link java.io.PrintWriter} to the standard output of Burp.
     * @return The standard output
     */
    public static PrintWriter getStdOut(){
        return stdout;
    }
    
    /**
     * Get a {@link java.io.PrintWriter} to the standard error output of Burp.
     * @return The standard error output
     */    
    public static PrintWriter getStdErr(){
        return stderr;
    }
 
}
