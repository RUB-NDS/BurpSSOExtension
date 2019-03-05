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
package de.rub.nds.burp.utilities.protocols;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.table.ssoHistory.Table;
import java.io.IOException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Object containing all information about a SAML message.
 * @author Tim Guenther
 * @version 1.0
 */
public class SAML extends SSOProtocol{

    /**
     * {@value #NAME}
     */
    public static final String NAME = "SAML";

    /**
     * {@value #REQUEST}
     */
    public static final String REQUEST = "SAMLRequest";

    /**
     * {@value #RESPONSE}
     */
    public static final String RESPONSE = "SAMLResponse";

    /**
     * {@value #RELAYSTATE}
     */
    public static final String RELAYSTATE = "RelayState";

    /**
     * {@value #ARTIFACT}
     */
    public static final String ARTIFACT = "SAMLart";
    
    /**
     * Create a new SAML object.
     * @param message The http message.
     * @param protocol The protocol name.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     * @param param The {@link burp.IParameter} with {@link #REQUEST} or
     * {@link #RESPONSE}.
     */
    public SAML(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks, IParameter param){
        super(message, protocol, callbacks);
        super.setParamName(param.getName());
        super.setParsedContent(decode(param.getValue()));
        super.setToken(findToken());
        super.setProtocolflowID(analyseProtocol());
        add(this, getProtocolflowID());
    }
    
    /**
     * Find the token associated to the request/response.
     * @return The token.
     */
    public String findToken(){
        Matcher m;
        Pattern p;
        switch (super.getParamName()) {
            case REQUEST:
                p = Pattern.compile("ID=\"(.*?)\"");
                break;
            case RESPONSE:
                p = Pattern.compile("InResponseTo=\"(.*?)\"");
                break;
            case ARTIFACT:
                p = Pattern.compile("InResponseTo=\"(.*?)\"");
                break;
            default:
                return "Not Found!";
        }
        if(super.getParsedContent() != null){
            m = p.matcher(super.getParsedContent());
            if(m.find()){
                return m.group(1);
            }
        }
        return "Not Found!";
    }
    
    /**
     * Decode inflated Base64 encoded data.
     * @param input Encoded data.
     * @return Decoded data.
     */
    @Override
    public String decode(String input){
        if(Encoding.getEncoding(input) == -1){
            return input;
        }
        switch (super.getParamName()) {
            case REQUEST:
                if(Encoding.isURLEncoded(input)){
                    input = super.getHelpers().urlDecode(input);
                    if(Encoding.getEncoding(input) < 0){
                        return input;
                    }
                }
                byte[] byteString = null;
                if(Encoding.isBase64Encoded(input)){
                    byteString = super.getHelpers().base64Decode(input);
                } else {
                    byteString = super.getHelpers().stringToBytes(input);
                }
                byte[] decompressed = null;
                {
                    try {
                        if(Encoding.isDeflated(byteString)){
                            try{
                                decompressed = Compression.decompress(byteString);
                            }catch(Exception ex){
                                Logger.getLogger(SAML.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            if(decompressed != null){
                                String result = new String(decompressed);
                                return result;
                            }
                        } else {
                            return input;
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(SAML.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            case RESPONSE:
                return super.getHelpers().bytesToString(super.getHelpers().base64Decode(super.getHelpers().urlDecode(input)));
        }
        return null;
    }
    
    /**
     * Analyse the protocol for the right table.
     * @return The protocol flow id.
     */
    @Override
    public int analyseProtocol() {
        //printOut("\nAnalyse: "+getProtocol()+" with ID: "+getToken());
        Logging.getInstance().log(getClass(), "Analyse: "+getProtocol()+" with ID: "+getToken(), Logging.DEBUG);
        ArrayList<SSOProtocol> last_protocolflow = SSOProtocol.getLastProtocolFlow();
        if(last_protocolflow != null){
            double listsize = (double) last_protocolflow.size();
            double protocol = 0;
            double token = 0;
            //printOut("Size:"+listsize);
            String protocols = "";
            for(SSOProtocol sso : last_protocolflow){
                if(sso.getProtocol().equals(this.getProtocol())){
                    protocols += sso.getProtocol()+" ";
                    protocol++;
                }
                if(sso.getToken().equals(this.getToken())){
                    //printOut(sso.getToken());
                    token++;
                }
            }
            Logging.getInstance().log(getClass(), "("+protocols+")", Logging.DEBUG);
            if(listsize >= 0){
                double prob = ((protocol/listsize)*2+(token/listsize))/3;
                //printOut("Probability: "+prob);
                Logging.getInstance().log(getClass(), "Probability: "+prob, Logging.DEBUG);
                if(prob >= 0.7){
                    return getIDOfLastList();
                }
            }
            
        }
        return newProtocolflowID();
    }
    
    public static Table analyseProtocol(SSOProtocol startEntry, ArrayList<SSOProtocol> list){
        return null;
    }
}
