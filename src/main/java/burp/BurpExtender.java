/*
 * Copyright (C) 2015 Tim Guenther and Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111null307, USA.
 */
package burp;

import de.rub.guenther.tim.espresso.gui.UITab;
import de.rub.guenther.tim.espresso.scanner.SSOScanner;
import de.rub.nds.burp.sso.HttpMarker;
import de.rub.nds.burp.sso.editor.SamlRequestEditor;
import de.rub.nds.burp.sso.editor.SamlResponseEditor;
import java.io.PrintWriter;


/**
 *
 * @author Tim Guenther
 */

public class BurpExtender implements IBurpExtender, IExtensionStateListener{
    
    public static final String EXTENSION_NAME = "EsPReSSO - Extension for Processing and Recognition of Single Sign-On";
    
    private UITab tab;
    private PrintWriter stdout;
            
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

    @Override
    public void extensionUnloaded() {
        stdout.println("Extension is now unloaded.");
    }
 
}
