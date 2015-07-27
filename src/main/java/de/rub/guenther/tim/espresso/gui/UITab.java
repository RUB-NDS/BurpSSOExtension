/*
 * Copyright (C) 2015 Tim Guenther
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
package de.rub.guenther.tim.espresso.gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

/**
 *
 * @author Tim Guenther
 */
public class UITab implements ITab {
    
    //public UIPanel panel;
    private UIMain main;
    private final IBurpExtenderCallbacks callbacks;
    
    
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }
    
    @Override
    public Component getUiComponent() {
        return main;
    }
    
    public UIMain getUiMain(){
        return main;
    }
    
    @Override
    public String getTabCaption() {
        return "EsPReSSO";
    }
}
