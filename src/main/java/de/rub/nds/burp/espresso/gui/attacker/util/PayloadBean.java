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
package de.rub.nds.burp.espresso.gui.attacker.util;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import wsattacker.library.signatureWrapping.option.Payload;

/**
 * PayloadBean
 * @author Christian Mainka
 * @version 1.0
 */

public class PayloadBean {

	private Payload payload;

    /**
     * Property of payload.
     */
    public static final String PROP_PAYLOAD = "payload";

	private transient final PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport(this);

	/**
	 * Get the value of payload
	 *
	 * @return the value of payload
	 */
	public Payload getPayload() {
		return payload;
	}

	/**
	 * Set the value of payload
	 *
	 * @param payload new value of payload
	 */
	public void setPayload(Payload payload) {
		Payload oldPayload = this.payload;
		this.payload = payload;
		propertyChangeSupport.firePropertyChange(PROP_PAYLOAD, oldPayload, payload);
	}

	/**
	 * Add PropertyChangeListener.
	 *
	 * @param listener {@link java.beans.PropertyChangeListener}
	 */
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		propertyChangeSupport.addPropertyChangeListener(listener);
	}

	/**
	 * Remove PropertyChangeListener.
	 *
	 * @param listener {@link java.beans.PropertyChangeListener}
	 */
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		propertyChangeSupport.removePropertyChangeListener(listener);
	}

}