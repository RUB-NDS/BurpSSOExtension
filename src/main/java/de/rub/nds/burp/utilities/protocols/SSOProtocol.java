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
import org.apache.commons.codec.digest.DigestUtils;

/**
 * SSOProtocol.
 * The template for all SSO Protocols.
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class SSOProtocol {
    
    private static int max_protocol_id = -1;
    private static ArrayList<ArrayList<SSOProtocol>> protocolDB = new ArrayList<ArrayList<SSOProtocol>>();
    private ArrayList<SSOProtocol> protocolflow = new ArrayList<SSOProtocol>();

    //Unique id for all messages of the same protocol flow.
    private int protocolflow_id = -1;
    private int counter = -1;
    private long timestamp = 0;
    
    private IHttpRequestResponse message = null;
    private String protocol = null;
    private String parsedContent = null;
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
     * @param message The http message.
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
     * Get the last protocol flow.
     * @return The last protocol flow.
     */
    public static ArrayList<SSOProtocol> getLastProtocolFlow(){
        if(protocolDB.size()-1 < 0){
            return null;
        }
        return protocolDB.get(protocolDB.size()-1);
    }
    
    /**
     * Get the id of the last list stored in the protocol database.
     * @return The id of the last list.
     */
    public static int getIDOfLastList(){
        return protocolDB.size()-1;
    }
    
    /**
     * Generate a new protocol flow id.
     * @return The protocol flow id.
     */
    public static int newProtocolflowID(){
        max_protocol_id++;
        return max_protocol_id;
    }
    
    
/** ------------------------------------------------------------------------- */     
/** Abstract. --------------------------------------------------------------- */   
    
    /**
     * Analyse the protocol for the right table.
     * @return The protocol flow id.
     */
    abstract public int analyseProtocol();

    /**
     * Decode the input as needed for the specific protocol.
     * @param input The plain data.
     * @return The decoded data.
     */
    abstract public String decode(String input);

    /**
     * Find the token associated to the request/response.
     * @return The token.
     */
    abstract public String findToken();
    
/** ------------------------------------------------------------------------- */ 
/** GETTER. ----------------------------------------------------------------- */
    
    /**
     * Get the code style.
     * Needed for the {@link org.fife.ui.rsyntaxtextarea.RSyntaxTextArea}.<br>
     * Not set during construction.
     * @return the code style.
     */
    public String getCodeStyle(){
        return codeStyle;
    }
    
    /**
     * Get the index of the Protocol in the table.
     * @return The index.
     */
    public int getCounter(){
        return counter;
    }
    
    /**
     * Get the http message.
     * @return The http message
     */
    public IHttpRequestResponse getMessage(){
        return message;
    }    
    
    /**
     * Get the parsed content.
     * This could be a earlier found i.e. parameter.
     * @return The parsed content.
     */
    public String getParsedContent(){
        return parsedContent;
    }
    
    /**
     * Get the parameter name.
     * This is corresponding to {@link #setParsedContent(java.lang.String) }
     * @return The parameter name.
     */
    public String getParamName(){
        return paramName;
    }
    
    /**
     * Get the protocol name.
     * @return The protocol name.
     */
    public String getProtocol(){
        return protocol;
    }
    
    /**
     * Get the protocol flow.
     * The protocol flow is generated by {@link #analyseProtocol() }.
     * @return A list of SSO protocols.
     */
    public ArrayList<SSOProtocol> getProtocolFlow(){
        return protocolflow;
    }    
    
    /**
     * Get the protocol flow id.
     * @return The protocol flow id.
     */
    public int getProtocolflowID(){
        return protocolflow_id;
    }
    
    /**
     * Get the timestamp.
     * The timestamp is a value generated by {@link System#currentTimeMillis()}.
     * @return The timestamp.
     */
    public long getTimestamp(){
        return timestamp;
    }
    
    /**
     * Get the token.
     * This is an identification characteristic for the protocol.
     * @return The token.
     */
    public String getToken(){
        return token;
    }
    
    

    /**
     * Get {@link burp.IBurpExtenderCallbacks}
     * @return {@link burp.IBurpExtenderCallbacks}
     */
    protected IBurpExtenderCallbacks getCallbacks(){
        return callbacks;
    }
    
    /**
     * Get {@link burp.IExtensionHelpers}
     * @return {@link burp.IExtensionHelpers}
     */
    protected IExtensionHelpers getHelpers(){
        return helpers;
    }
/** ------------------------------------------------------------------------- */    
/** SETTER. ----------------------------------------------------------------- */
   
    /**
     * Get the code style.
     * Needed for the {@link org.fife.ui.rsyntaxtextarea.RSyntaxTextArea}.<br>
     * Not set during construction.
     * @param codeStyle The code style.
     */
    protected void setCodeStyle(String codeStyle)
    {
        this.codeStyle = codeStyle;
    }
    
    /**
     * Set the counter.
     * @param i The counter position.
     */
    public void setCounter(int i){
        this.counter = i;
    }
    
    /**
     * Set the http message.
     * @param message The http message.
     */
    public void setMessage(IHttpRequestResponse message){
        this.message = message;
    }
    
    /**
     * Get the parsed content.
     * This could be a earlier found i.e. parameter.
     * @param content The parsed content.
     */
    protected void setParsedContent(String content){
        this.parsedContent = content;
    }
    
    /**
     * Set the token.     
     * This is an identification characteristic for the protocol.
     * @param token The token.
     */
    protected void setToken(String token){
        this.token = token;
    }
    
    /**
     * Set the parameter name.
     * This is corresponding to {@link #setParsedContent(java.lang.String) }.
     * @param paramName The name of the parameter.
     */
    public void setParamName(String paramName){
        this.paramName = paramName;
    }
    
    /**
     * Set the protocol name.
     * @param protocol The protocol name.
     */
    protected void setProtocol(String protocol){
        this.protocol = protocol;
    }
    
    /**
     * Set the protocol flow.
     * @param protocolflow A list with SSO protocols.
     */
    public void setProtocolFlow(ArrayList<SSOProtocol> protocolflow){
        this.protocolflow = protocolflow;
    }    
    
    /**
     * Set the protocol flow id.
     * @param id The protocol flow id.
     */
    public void setProtocolflowID(int id){
        protocolflow_id = id;
    }
/** ------------------------------------------------------------------------- */    
    
    /**
     * Convert SSOProtocol to a String.
     * @return Token + Protocol + md5(Request)
     */
    @Override
    public String toString(){
        return token+" "+protocol+" md5(Request)="+DigestUtils.md5(message.getRequest());
    }
    
    /**
     * Covert SSOProtocol to {@link de.rub.nds.burp.utilities.table.TableEntry}.
     * @return {@link de.rub.nds.burp.utilities.table.TableEntry}
     */
    public TableEntry toTableEntry(){
        return new TableEntry(this, callbacks);
    }
    
    /**
     * Covert SSOProtocol to {@link de.rub.nds.burp.utilities.table.Table}.
     * @param tableName The name of the table.
     * @param id The table id.
     * @return {@link de.rub.nds.burp.utilities.table.Table}
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
     * Add a new Protocol to the protocol database.
     * @param sso The SSOProtocol flow id.
     * @param id The protocol flow id.
     * @return True if successful, false otherwise.
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
     * Get the protocol flow by its index.
     * @param i The index.
     * @return The protocol flow.
     */
    public ArrayList<SSOProtocol> get(int i){
        return protocolDB.get(i);
    }
    
    /**
     * Update all protocol names of the same protocol flow.
     * @param protocol The new protocol name.
     * @return True if protocol flow not null, false otherwise.
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
