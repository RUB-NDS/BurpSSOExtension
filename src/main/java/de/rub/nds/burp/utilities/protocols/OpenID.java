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
import de.rub.nds.burp.utilities.Logging;
import static de.rub.nds.burp.utilities.protocols.SSOProtocol.getIDOfLastList;
import static de.rub.nds.burp.utilities.protocols.SSOProtocol.newProtocolflowID;
import java.util.ArrayList;
import java.util.List;

/**
 * OpenID
 * @author Tim Guenther
 * @version 1.0
 */
public class OpenID extends SSOProtocol{
    
    /**
     * {@value #OPENID_V1}
     */
    public static final String OPENID_V1 = "OpenID v1.0";

    /**
     * {@value #OPENID_PARAM}
     */
    public static final String OPENID_PARAM = "openid.mode";

    /**
     * {@value #OPENID_REQUEST}
     */
    public static final String OPENID_REQUEST = "checkid_setup";

    /**
     * {@value #OPENID_RESPONSE}
     */
    public static final String OPENID_RESPONSE = "id_res";

    /**
     * {@value #ID}
     */
    public static final String ID = "openid.identity";

    /**
     * {@value #OPENID_V2}
     */
    public static final String OPENID_V2 = "OpenID v2.0";
    
    private String return_to = "";
    
    /**
     * Create a new OpenID object.
     * @param message The http message.
     * @param protocol The protocol name.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public OpenID(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks){
        super(message, protocol, callbacks);
        super.setToken(findToken());
        super.setProtocolflowID(analyseProtocol());
        add(this, getProtocolflowID());
    }

    /**
     * URL decode input.
     * @param input The plain data.
     * @return The decoded data.
     */
    @Override
    public String decode(String input) {
        if(Encoding.isURLEncoded(input)){
            return super.getCallbacks().getHelpers().urlDecode(input);
        }
        return input;
    }

    /**
     * Find the token associated to the request/response.
     * @return The token.
     */
    @Override
    public String findToken() {
          IRequestInfo iri = super.getCallbacks().getHelpers().analyzeRequest(super.getMessage());
          List<IParameter> list = iri.getParameters();
          String id = "Not Found!";
          for(IParameter p : list){
              if(p.getName().equals("openid.identity")){
                  id = decode(p.getValue());
                  continue;
              }
              if(p.getName().equals("openid.return_to")){
                  return_to = p.getValue();
              }
          }
          return id;
    }
    
    private String findReturnTo(IHttpRequestResponse message){
        IRequestInfo iri = super.getCallbacks().getHelpers().analyzeRequest(message);
          List<IParameter> list = iri.getParameters();
          String returnTo = null;
          for(IParameter p : list){
              if(p.getName().equals("openid.return_to")){
                  returnTo = p.getValue();
                  break;
              }
          }
          return returnTo;
    }

    /**
     * Analyse the protocol for the right table.
     * @return The protocol flow id.
     */
    @Override
    public int analyseProtocol() {
        logging.log(getClass(), "\nAnalyse: "+getProtocol()+" with ID: "+getToken(), Logging.DEBUG);
        ArrayList<SSOProtocol> last_protocolflow = SSOProtocol.getLastProtocolFlow();
        if(last_protocolflow != null){
            double listsize = (double) last_protocolflow.size();
            double protocol = 0;
            double token = 0;
            double traffic = 0;
            for(SSOProtocol sso : last_protocolflow){
                if(sso.getProtocol().substring(0, 5).equals(this.getProtocol().substring(0, 5))){
                    logging.log(getClass(), sso.getProtocol(), Logging.DEBUG);
                    protocol++;
                }
                if(sso.getToken().equals(this.getToken())){
                    logging.log(getClass(),sso.getToken(), Logging.DEBUG);
                    token++;
                }
                String returnTo = findReturnTo(sso.getMessage());
                if(returnTo != null){
                    if(return_to.equals(returnTo)){
                        logging.log(getClass(),returnTo, Logging.DEBUG);
                        traffic++;
                    }
                }
                
            }
            
            if(listsize >= 0){
                double prob = ((protocol/listsize)+(token/listsize)+(traffic/listsize))/3;
                logging.log(getClass(),"Probability: "+prob, Logging.DEBUG);
                if(prob >= 0.7){
                    return getIDOfLastList();
                }
            }
            
        }
        return newProtocolflowID();
    }

}
