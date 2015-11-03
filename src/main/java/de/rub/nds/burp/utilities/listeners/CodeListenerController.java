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

import javax.swing.event.EventListenerList;

/**
 * CodeListener Controller
 * @author Tim Guenther
 * @version 1.0
 */
public class CodeListenerController {
    private EventListenerList listeners = new EventListenerList();
    
    /**
     * Default Constructor.
     */
    public CodeListenerController(){
    }
    
    /**
     * Add a new implementation of {@link de.rub.nds.burp.utilities.listeners.ICodeListener}
     * @param listener The new listener.
     */
    public void addCodeListener(ICodeListener listener){
      listeners.add(ICodeListener.class, listener);
    }

    /**
     * Remove the {@link de.rub.nds.burp.utilities.listeners.ICodeListener}
     * @param listener The listener to remove.
     */
    public void removeCodeListener(ICodeListener listener){
      listeners.remove(ICodeListener.class, listener);
    }

    /**
     * Notify all registered listeners with the new code.
     * @param event The event.
     */
    public synchronized void notifyAll(AbstractCodeEvent event)
    {
        for (ICodeListener l : listeners.getListeners(ICodeListener.class)){
            l.setCode(event);
        }
    }
    
    
}
