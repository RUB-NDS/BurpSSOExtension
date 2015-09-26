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
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.table.Table;
import de.rub.nds.burp.utilities.table.TableEntry;
import de.rub.nds.burp.utilities.table.TableHelper;
import java.util.ArrayList;

/**
 * SSOProtocol.
 * The template for all SSO Protocols.
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class SSOProtocol {
    //constants

    /**
     *
     */
    public static final String SAML = "SAML";

    /**
     *
     */
    public static final String SAML_REQUEST = "SAMLRequest";

    /**
     *
     */
    public static final String SAML_RESPONSE = "SAMLResponse";

    /**
     *
     */
    public static final String SAML_RELAYSTATE = "RelayState";

    /**
     *
     */
    public static final String SAML_ARTIFACT = "SAMLart";
    
    /**
     *
     */
    public static final String OPENID_V1 = "OpenID v1.0";

    /**
     *
     */
    public static final String OPENID_PARAM = "openid.mode";

    /**
     *
     */
    public static final String OPENID_REQUEST = "checkid_setup";

    /**
     *
     */
    public static final String OPENID_RESPONSE = "id_res";

    /**
     *
     */
    public static final String OPENID_ID = "openid.identity";

    /**
     *
     */
    public static final String OPENID_V2 = "OpenID v2.0";
    
    /**
     *
     */
    public static final String OPENID_CONNECT = "OpenID Connect";
    
    /**
     *
     */
    public static final String OAUTH_V1 = "OAuth v1.0";

    /**
     *
     */
    public static final String OAUTH_V2 = "OAuth v2.0";

    /**
     *
     */
    public static final String OAUTH_ID = "client_id";

    /**
     *
     */
    public static final String OAUTH_ID_FACEBOOK = "app_id";
    
    /**
     *
     */
    public static final String BROWSERID = "BrowserID";

    /**
     *
     */
    public static final String BROWSERID_ID = "browserid_state";
    
    private static int max_protocol_id = -1;
    private static ArrayList<ArrayList<SSOProtocol>> protocolDB = new ArrayList<ArrayList<SSOProtocol>>();
    private ArrayList<SSOProtocol> protocolflow = new ArrayList<SSOProtocol>();
    
    private IHttpRequestResponse message;
    //Unique id for all messages of the same protocol flow.
    private int protocolflow_id = -1;
    private int counter = -1;
    private long timestamp = 0;
    
    private String protocol = null;
    private String content = null;
    private String paramName = null;
    private String token = "Not Found!";
    private String codeStyle = null;
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    /**
     * Internal logger.
     */
    protected Logging logging = Logging.getInstance();

    /**
     * Template to create a new SSOProtocol Instance.
     * @param message The http messes from Burp-
     * @param protocol The protocol name.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public SSOProtocol(IHttpRequestResponse message, String protocol, IBurpExtenderCallbacks callbacks){
        this.message = message;
        this.protocol = protocol;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.timestamp = System.currentTimeMillis();
    }
    
/** Static. --------------------------------------------------------------- */  

    /**
     *
     * @return
     */
    public static ArrayList<SSOProtocol> getLastProtocolFlow(){
        if(protocolDB.size()-1 < 0){
            return null;
        }
        return protocolDB.get(protocolDB.size()-1);
    }
    
    /**
     *
     * @return
     */
    public static int getIDOfLastList(){
        return protocolDB.size()-1;
    }
    
        /**
     *
     * @return
     */
    public static int newProtocolflowID(){
        max_protocol_id++;
        return max_protocol_id;
    }
    
    
/** ------------------------------------------------------------------------- */     
/** Abstract. --------------------------------------------------------------- */   
    
    /**
     *
     * @return
     */
    abstract public int analyseProtocol();

    /**
     *
     * @param input
     * @return
     */
    abstract public String decode(String input);

    /**
     *
     * @return
     */
    abstract public String findID();
    
/** ------------------------------------------------------------------------- */ 
/** GETTER. ----------------------------------------------------------------- */
    
    /**
     *
     * @return
     */
    public String getCodeStyle(){
        return codeStyle;
    }
    
    /**
     *
     * @return
     */
    public String getContent(){
        return content;
    }
    
    /**
     *
     * @return
     */
    public IHttpRequestResponse getMessage(){
        return message;
    }    
    
    /**
     *
     * @return
     */
    public String getParamName(){
        return paramName;
    }
    
    /**
     *
     * @return
     */
    public String getProtocol(){
        return protocol;
    }
    
    /**
     *
     * @return
     */
    public ArrayList<SSOProtocol> getProtocolFlow(){
        return protocolflow;
    }    
    
    /**
     *
     * @return
     */
    public int getProtocolflowID(){
        return protocolflow_id;
    }
    
    /**
     *
     * @return
     */
    public long getTimestamp(){
        return timestamp;
    }
    
        /**
     *
     * @return
     */
    public String getToken(){
        return token;
    }

    /**
     *
     * @return
     */
    protected IBurpExtenderCallbacks getCallbacks(){
        return callbacks;
    }
    
    /**
     *
     * @return
     */
    protected IExtensionHelpers getHelpers(){
        return helpers;
    }
/** ------------------------------------------------------------------------- */    
/** SETTER. ----------------------------------------------------------------- */
   
    /**
     *
     * @param codeStyle
     */
    protected void setCodeStyle(String codeStyle)
    {
        this.codeStyle = codeStyle;
    }
    
    /**
     *
     * @param content
     */
    protected void setContent(String content){
        this.content = content;
    }
    
    /**
     *
     * @param i
     */
    public void setCounter(int i){
        this.counter = i;
    }
    
    /**
     *
     * @param message
     */
    public void setMessage(IHttpRequestResponse message){
        this.message = message;
    }    
        
    /**
     *
     * @param token
     */
    protected void setToken(String token){
        this.token = token;
    }
    
    /**
     *
     * @param paramName
     */
    public void setParamName(String paramName){
        this.paramName = paramName;
    }
    
    /**
     *
     * @param protocol
     */
    protected void setProtocol(String protocol){
        this.protocol = protocol;
    }
    
    /**
     *
     * @param protocolflow
     */
    public void setProtocolFlow(ArrayList<SSOProtocol> protocolflow){
        this.protocolflow = protocolflow;
    }    
    
    /**
     *
     * @param id
     */
    public void setProtocolflowID(int id){
        protocolflow_id = id;
    }
    
    /**
     *
     * @return
     */
    public int getCounter(){
        return counter;
    }
    

/** ------------------------------------------------------------------------- */    
    
    /**
     *
     * @return
     */
    @Override
    public String toString(){
        return token+" "+protocol+" "+paramName+"="+content;
    }
    
    /**
     *
     * @return
     */
    public TableEntry toTableEntry(){
        return new TableEntry(this, callbacks);
    }
    
    /**
     *
     * @param tableName
     * @param id
     * @return
     */
    public Table toTable(String tableName, String id){
        Table t = new Table(new TableHelper(new ArrayList<TableEntry>()),tableName,id);
        int i = 1;
        for(SSOProtocol sso : protocolflow){
            TableEntry e = sso.toTableEntry();
            e.setCounter(i++);
            t.getTableHelper().addRow(e);
        }
        if(t.getTableList().size() >= 0){
            return t;
        }
        logging.log(getClass(), "Table "+id+" is null.", Logging.ERROR);
        return null;
    }

    /**
     *
     * @param sso
     * @param id
     * @return
     */
    public boolean add(SSOProtocol sso, int id){
        if(protocolDB.size()-1 < id){
            protocolflow.add(sso);
            protocolDB.add(protocolflow);
            if(protocolDB.size()-1 == id){
                return true;
            }
            return false;
        }
        protocolDB.get(id).add(sso);
        protocolflow = protocolDB.get(id);
        return true;
    }
    
    /**
     *
     * @param i
     * @return
     */
    public ArrayList<SSOProtocol> get(int i){
        return protocolDB.get(i);
    }
    
    /**
     *
     * @param protocol
     * @return
     */
    public boolean updateProtocols(String protocol){
        if(protocolflow != null){
            for(SSOProtocol sso : protocolflow){
                sso.setProtocol(protocol);
            }
            return true;
        }
        return false;
    }
}
