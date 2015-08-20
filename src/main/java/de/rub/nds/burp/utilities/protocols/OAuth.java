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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Tim Guenther
 */
public class OAuth extends SSOProtocol{
    
    private IHttpRequestResponse ihrr; 

    public OAuth(IParameter param, IBurpExtenderCallbacks callbacks, IHttpRequestResponse ihrr) {
        super(param, callbacks);
        super.setProtocol(OAUTH_V2);
        this.ihrr = ihrr;
        super.setToken(findID());
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
            if(p.getName().equals(SSOProtocol.OAUTH_ID)){
                return decode(p.getValue());
            }
            if(p.getName().equals(SSOProtocol.OAUTH_ID_FACEBOOK)){
                return decode(p.getValue());
            }
        }
        String response = super.getCallbacks().getHelpers().bytesToString(ihrr.getResponse());
        Pattern p = Pattern.compile("client_id=(.*?)\\\\u0026");
        Matcher m = p.matcher(response);
        if(m.find()){
            return m.group(1);
        }
        return "Not Found!";
    }

    @Override
    public int analyseProtocol() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
