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
import de.rub.nds.burp.utilities.Encoding;
import static de.rub.nds.burp.utilities.protocols.SSOProtocol.getIDOfLastList;
import static de.rub.nds.burp.utilities.protocols.SSOProtocol.newProtocolflowID;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Tim Guenther
 */
public class OpenID extends SSOProtocol{

    public OpenID(IParameter param, IBurpExtenderCallbacks callbacks, String protocol, IHttpRequestResponse ihrr) {
        super(param, callbacks);
        super.setProtocol(protocol);
        super.setMessage(ihrr);
        super.setToken(findID());                
    }
    
    public OpenID(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks){
        super(message, protocol, callbacks);
        super.setToken(findID());
        super.setProtocolflowID(analyseProtocol());
        add(this, getProtocolflowID());
    }

    @Override
    public String decode(String input) {
        if(Encoding.isURLEncoded(input)){
            return super.getCallbacks().getHelpers().urlDecode(input);
        }
        return input;
    }

    @Override
    public String findID() {
          IRequestInfo iri = super.getCallbacks().getHelpers().analyzeRequest(super.getMessage());
          List<IParameter> list = iri.getParameters();
          for(IParameter p : list){
              if(p.getName().equals("openid.identity")){
                  return decode(p.getValue());
              }
          }
          return "Not Found!";
    }

    @Override
    public int analyseProtocol() {
        ArrayList<SSOProtocol> last_protocolflow = SSOProtocol.getLastProtocolFlow();
        if(last_protocolflow != null){
            double listsize = (double) last_protocolflow.size();
            double protocol = 0;
            double token = 0;
            for(SSOProtocol sso : last_protocolflow){
                if(sso.getProtocol().equals(this.getProtocol())){
                    printOut(sso.getProtocol());
                    protocol++;
                }
                if(sso.getToken().equals(this.getToken())){
                    printOut(sso.getToken());
                    token++;
                } 
            }
            if(listsize >= 0){
                double prob = ((protocol/listsize)*2+(token/listsize))/3;
                if(prob >= 0.7){
                    return getIDOfLastList();
                }
            }
            
        }
        return newProtocolflowID();
    }

}
