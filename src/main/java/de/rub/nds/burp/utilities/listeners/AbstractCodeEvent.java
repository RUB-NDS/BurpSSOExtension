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
package de.rub.nds.burp.utilities.listeners;

import java.util.EventObject;

/**
 * Abstract Code Event
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class AbstractCodeEvent extends EventObject{
    
    private String code;

    /**
     * Template to create a new CodeEvent.
     * @param source The origin of the event.
     * @param code The data (source code) to submit.
     */
    public AbstractCodeEvent(Object source, String code) {
        super(source);
        this.code = code;
    }
    
    /**
     * Get the Source Code.
     * @return The source code.
     */
    public String getCode(){
        return code;
    }
    
}
