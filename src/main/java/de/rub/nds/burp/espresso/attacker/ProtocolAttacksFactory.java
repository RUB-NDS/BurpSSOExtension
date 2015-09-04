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
package de.rub.nds.burp.espresso.attacker;

import de.rub.nds.burp.espresso.attacker.attacks.IProtocolAttacks;
import de.rub.nds.burp.espresso.attacker.attacks.SAMLAttacks;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;

/**
 *
 * @author Tim Guenther
 */
public class ProtocolAttacksFactory {
    private ProtocolAttacksFactory(){}
    
    private static class SingletonHolder {
        private static final ProtocolAttacksFactory INSTANCE = new ProtocolAttacksFactory();
    }

    public static ProtocolAttacksFactory getInstance() {
        return SingletonHolder.INSTANCE;
    }
    
    public IProtocolAttacks getAttacks(SSOProtocol sso){
        String protocol = sso.getProtocol();
        switch(protocol){
            case SSOProtocol.SAML:
                return new SAMLAttacks();
            default:
                Logging.getInstance().log(getClass().getName(), "No Attack for {"+protocol+"} found.", true);
        }
        return null;
    }
}
