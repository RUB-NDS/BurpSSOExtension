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
import burp.IParameter;

/**
 *
 * @author Tim Guenther
 */
public abstract class SSOProtocol {
    //constants
    public static final String SAML = "SAML";
    public static final String SAML_REQUEST = "SAMLRequest";
    public static final String SAML_RESPONSE = "SAMLResponse";
    public static final String SAML_RELAYSTATE = "RelayState";
    public static final String SAML_ARTUFACT = "SAMLart";
    
    public static final String OPENID_V1 = "OpenID v1.0";
    public static final String OPENID_PARAM = "openid.mode";
    public static final String OPENID_REQUEST = "checkid_setup";
    public static final String OPENID_RESPONSE = "id_res";
    
    public static final String OPENID_V2 = "OpenID v2.0";
    public static final String OPENID_CONNECT = "OpenID Connect";
    public static final String OAUTH_V1 = "OAuth v1.0";
    public static final String OAUTH_V2 = "OAuth v2.0";
    public static final String BROWSERID = "BrowserID";
    
    private String protocol = null;
    private String content = null;
    private String paramName = null;
    private String id = null;
    private String codeStyle = null;
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    public SSOProtocol(){        
    }

    public SSOProtocol(IParameter param, IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.paramName = param.getName();
        this.content = param.getValue();
    }
    
    abstract public String decode(String input);
    abstract public String findID();
    
    public String getContent(){
        return content;
    }
    
    public String getParamName(){
        return paramName;
    }
    
    public String getID(){
        return id;
    }
    
    public String getProtocol(){
        return protocol;
    }
    
    public String getCodeStyle(){
        return codeStyle;
    }
    
    protected IBurpExtenderCallbacks getCallbacks(){
        return callbacks;
    }
    
    protected IExtensionHelpers getHelpers(){
        return helpers;
    }
    
    protected void setCodeStyle(String codeStyle)
    {
        this.codeStyle = codeStyle;
    }
    
    protected void setID(String id){
        this.id = id;
    }
    
    protected void setContent(String content){
        this.content = content;
    }
    
    protected void setProtocol(String protocol){
        this.protocol = protocol;
    }
    
    @Override
    public String toString(){
        return id+" "+protocol+" "+paramName+"="+content;
    }
}
