package de.rub.nds.burp.espresso.attacker.attacks;

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

import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import javax.swing.JPanel;
import wsattacker.library.signatureFaking.SignatureFakingOracle;
import wsattacker.library.signatureFaking.exceptions.SignatureFakingException;

/**
 * Interface for external libraries.
 * TODO use Google Java Protobuff for IPC.
 * https://developers.google.com/protocol-buffers/
 * @author Tim Guenther
 * @version 1.0
 */
public class SAMLSigFakeAttack implements IAttackAdapter{
    private final String name = "Signature Faking";
    private JPanel lastPanel = null;

    @Override
    public boolean startAttack(Object o) {
        SSOProtocol sso = (SSOProtocol) o;
        try {
            SignatureFakingOracle sof = new SignatureFakingOracle(sso.getContent());
            sof.fakeSignatures();
            if(sof.getDocument() != null){
                Logging.getInstance().log(getClass().getName(), "Document successfully faked.", false);
                return true;
            }
        } catch (SignatureFakingException ex) {
            Logging.getInstance().log(getClass().getName(), ex.getMessage(), true);
        }
        return false;
    }

    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public JPanel getNextPanel(JPanel currPanel) {
        lastPanel = currPanel;
        JPanel demo = new DemoAttackDetailPanel();
        return demo;
    }

    @Override
    public JPanel getLastPanel() {
        return lastPanel;
    }
    
}
