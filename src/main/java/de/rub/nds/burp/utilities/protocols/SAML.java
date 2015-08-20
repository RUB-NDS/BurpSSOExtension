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
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Encoding;
import java.io.IOException;
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
    private String content = null;
    private String paramName = null;
    private String id = null;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    /**
     * Default constructor.
     */
    public SAML(){
    }
    
    /**
     * Construct a SAML message.
     * @param saml SAML message.
     * @param paramName Parameter Name.
     */
    public SAML(String saml, String paramName){
        this.content = saml;
        this.paramName = paramName;
        this.id = findID();
    }
    
    /**
     * Construct a SAML message.
     * @param param A Burp Suite api for parameters. 
     * @param callbacks Provided by the Burp Suite api.
     */
    public SAML(IParameter param, IBurpExtenderCallbacks callbacks){
        this.paramName = param.getName();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.content = decode(param.getValue());
        this.id = findID();
    }
    
    public SAML(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks){
        super(message, protocol, callbacks);
        super.setProtocol(protocol);
    }
    
    
    public String getToken(){
        return id;
    }
    
    /**
     * Find the ID associated to the request/response.
     * @return ID
     */
    public String findID(){
        Matcher m;
        Pattern p;
        switch (paramName) {
            case SSOProtocol.SAML_REQUEST:
                p = Pattern.compile("ID=\"(.*?)\"");
                break;
            case SSOProtocol.SAML_RESPONSE:
                p = Pattern.compile("InResponseTo=\"(.*?)\"");
                break;
            case SSOProtocol.SAML_ARTIFACT:
                p = Pattern.compile("InResponseTo=\"(.*?)\"");
                break;
            default:
                return "Not Found!";
        }
        if(content != null){
            m = p.matcher(content);
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
        switch (paramName) {
            case SSOProtocol.SAML_REQUEST:
                if(Encoding.isURLEncoded(input)){
                    input = helpers.urlDecode(input);
                    if(Encoding.getEncoding(input) < 0){
                        return input;
                    }
                }
                byte[] byteString = null;
                if(Encoding.isBase64Encoded(input)){
                    byteString = helpers.base64Decode(input);
                } else {
                    byteString = helpers.stringToBytes(input);
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
            case SSOProtocol.SAML_RESPONSE:
                return helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(input)));
        }
        return null;
    }
    
    @Override
    public String toString(){
        return id+" "+paramName+"="+content;
    }

    @Override
    public int analyseProtocol() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
