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
import de.rub.nds.burp.utilities.table.TableEntry;
import java.util.ArrayList;

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
    public static final String SAML_ARTIFACT = "SAMLart";
    
    public static final String OPENID_V1 = "OpenID v1.0";
    public static final String OPENID_PARAM = "openid.mode";
    public static final String OPENID_REQUEST = "checkid_setup";
    public static final String OPENID_RESPONSE = "id_res";
    public static final String OPENID_ID = "openid.identity";
    public static final String OPENID_V2 = "OpenID v2.0";
    
    public static final String OPENID_CONNECT = "OpenID Connect";
    
    public static final String OAUTH_V1 = "OAuth v1.0";
    public static final String OAUTH_V2 = "OAuth v2.0";
    public static final String OAUTH_ID = "client_id";
    public static final String OAUTH_ID_FACEBOOK = "app_id";
    
    public static final String BROWSERID = "BrowserID";
    public static final String BROWSERID_ID = "browserid_state";
    
    private static int max_protocol_id = -1;
    private static ArrayList<ArrayList<SSOProtocol>> protocolDB = new ArrayList<ArrayList<SSOProtocol>>();
    private ArrayList<SSOProtocol> protocolflow = new ArrayList<SSOProtocol>();
    
    private IHttpRequestResponse message;
    //Unique id for all messages of the same protocol flow.
    private int protocolflow_id = -1;
    
    private String protocol = null;
    private String content = null;
    private String paramName = null;
    private String token = "Not Found!";
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
    
    public SSOProtocol(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks){
        this.message = message;
        this.protocol = protocol;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();        
    }
    
    //return id of table in protocolDB
    abstract public int analyseProtocol();
    abstract public String decode(String input);
    abstract public String findID();
    
    public String getContent(){
        return content;
    }
    
    public String getParamName(){
        return paramName;
    }
    
    public String getToken(){
        return token;
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
    
    protected void setToken(String token){
        this.token = token;
    }
    
    protected void setContent(String content){
        this.content = content;
    }
    
    protected void setProtocol(String protocol){
        this.protocol = protocol;
    }
    
    @Override
    public String toString(){
        return token+" "+protocol+" "+paramName+"="+content;
    }
    
    public static int newProtocolflowID(){
        max_protocol_id++;
        return max_protocol_id;
    }
    
    public void setProtocolflowID(int id){
        protocolflow_id = id;
    }
    
    public int getProtocolflowID(){
        return protocolflow_id;
    }
    
    public TableEntry toTableEntry(){
        return new TableEntry(this, callbacks);
    }
    
    public static ArrayList<SSOProtocol> getLastProtocolFlow(){
        return protocolDB.get(protocolDB.size());
    }
    
    public ArrayList<SSOProtocol> getProtocolFlow(){
        return protocolflow;
    }
    
    public IHttpRequestResponse getMessage(){
        return message;
    }
    
    public void setMessage(IHttpRequestResponse message){
        this.message = message;
    }
}
