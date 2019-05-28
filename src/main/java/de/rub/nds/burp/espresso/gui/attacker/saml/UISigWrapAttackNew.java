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
package de.rub.nds.burp.espresso.gui.attacker.saml;

import de.rub.nds.burp.espresso.gui.attacker.saml.xsw.UISigWrapAttackInit;
import de.rub.nds.burp.espresso.gui.attacker.saml.xsw.UISigWrapExec;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import javax.swing.JTabbedPane;

/**
 * The Signature Wrapping Attack
 * @author Nurullah Erinola
 * @version 1.0
 */
public class UISigWrapAttackNew extends JTabbedPane {
    
    private final String INIT = "Init Attack";
    private final String EXECUTE = "Execute Attack";
    
    private UISigWrapAttackInit uiInit;
    private UISigWrapExec uiExec;
      
    /**
     * Create new form UISigWrapAttackNew.
     */
    public UISigWrapAttackNew(){
        initComponents();
    }
    
    private void initComponents() {
        uiExec = new UISigWrapExec();
        uiInit = new UISigWrapAttackInit(uiExec);
        uiInit.setSwitchTabFunc((Integer i) -> selectTab(i));
        // Add to pane
        this.add(INIT, uiInit);
        this.add(EXECUTE, uiExec);
    }
    
    /**
     * Set the listener for the editor.
     * @param listeners {@link de.rub.nds.burp.utilities.listeners.CodeListenerController}
     */
    public void setListeners(CodeListenerController listeners){
        uiInit.setListener(listeners);
        uiExec.setListener(listeners);
    }

    private void selectTab(int index) {
        this.setSelectedIndex(index);
    }
}
