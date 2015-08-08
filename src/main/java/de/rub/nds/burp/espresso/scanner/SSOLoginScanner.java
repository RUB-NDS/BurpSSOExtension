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
package de.rub.nds.burp.espresso.scanner;

import burp.IHttpListener;
import burp.IHttpRequestResponse;

/**
 * Scan for Login possibilities on responses.
 * This class should check during browsing if a SSO login button is found and
 * give an alert/notification if one is found. this should be done protocol 
 * dependent.
 * @author Tim Guenther
 * @version 0.1
 * 
 * 
 */
public class SSOLoginScanner implements IHttpListener{

    public SSOLoginScanner() {
    }

    /**
    * Implementation of the IHttpListener interface.
    * Is called every time a request/response is processed by Burp Suite.
    * @param toolFlag A numeric identifier for the Burp Suite tool that calls. 
    * @param isRequest True for a request, false for a response.
    * @param httpRequestResponse The request/response that should processed.
    */
    @Override
    public void processHttpMessage(int toolFlag , boolean isRequest, IHttpRequestResponse httpRequestResponse) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
