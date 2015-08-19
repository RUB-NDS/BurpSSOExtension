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
package de.rub.nds.burp.utilities.protocols;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import java.util.List;

/**
 *
 * @author Tim Guenther
 */
public class BrowserID extends SSOProtocol{
    
    private IHttpRequestResponse ihrr;

    public BrowserID() {
    }

    public BrowserID(List<IParameter> parameterList, IBurpExtenderCallbacks callbacks, IHttpRequestResponse ihrr) {
        super(parameterList.get(0), callbacks);
        super.setProtocol(BROWSERID);
        this.ihrr = ihrr;
        super.setID(findID());
    }
    
    @Override
    public String decode(String input) {
        return input;
    }

    @Override
    public String findID() {
        IRequestInfo iri = super.getCallbacks().getHelpers().analyzeRequest(ihrr);
        List<IParameter> list = iri.getParameters();
        for(IParameter p : list){
            if(p.getName().equals(SSOProtocol.BROWSERID_ID)){
                return decode(p.getValue());
            }
        }
        return "Not Found!";
    }
    
}
