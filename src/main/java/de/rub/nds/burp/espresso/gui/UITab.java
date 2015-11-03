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
package de.rub.nds.burp.espresso.gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

/**
 * An additional tab in Burp Suite
 * @author Tim Guenther
 * @version 1.0
 */
public class UITab implements ITab {
    
    //public UIPanel panel;
    private UIMain main;
    private final IBurpExtenderCallbacks callbacks;
    
    /**
     * Create a new Tab.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }
    
    /**
     * 
     * @return Get the UI component that should be registered at the Burp Suite GUI. 
     */
    @Override
    public Component getUiComponent() {
        return main;
    }
    
    /**
     * 
     * @return Get the UI component that should be registered at the Burp Suite GUI.
     */
    public UIMain getUiMain(){
        return main;
    }
    
    /**
     * 
     * @return Get the Headline for the Tab. 
     */
    @Override
    public String getTabCaption() {
        return "EsPReSSO";
    }
}
