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
package de.rub.nds.burp.utilities.table.ssoHistory;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponsePersisted;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import java.time.LocalTime;
import java.util.ArrayList;

/**
 * A table entry for the class Table.
 * @author Tim Guenther
 * @version 1.0
 */
public class TableEntry {
    private Integer counter = 0;
    private String protocol = "";
    private String host = "";
    private String method = "";
    private String url = "";
    private String token = "";
    private String time = "";
    private LocalTime timestamp = null;
    private String length = "";
    private String comment = "";
    private IHttpRequestResponsePersisted fullMessage = null;
    private SSOProtocol ssoProtocol = null; 
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * Construct a new table entry.
     * @param counter The number of the entry position in the history. 
     * @param protocol The single sign-on protocol.
     * @param token The token or unique id for the protocol flow.
     * @param requestResponse The content of the request/response.
     * @param callbacks Helper provided by the Burp Suite api.
     */
    public TableEntry(Integer counter, String protocol, String token, IHttpRequestResponsePersisted requestResponse, IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        this.counter = counter;
        this.protocol = protocol;
        this.host = helpers.analyzeRequest(requestResponse).getUrl().getHost();
        this.method = helpers.analyzeRequest(requestResponse).getMethod();
        this.url = helpers.analyzeRequest(requestResponse).getUrl().getPath();
        this.token = token;
        LocalTime t = LocalTime.now();
        this.timestamp = t;
        this.time = t.toString().substring(0, t.toString().length()-2);
        this.length = (new Integer(requestResponse.getResponse().length)).toString();
        this.comment = requestResponse.getComment();
        this.fullMessage = requestResponse;
    }
    
    /**
     * Create a new table entry.
     * @param ssoProtocol The {@link SSOProtocol}.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public TableEntry(SSOProtocol ssoProtocol, IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        this.counter = ssoProtocol.getCounter();
        this.protocol = ssoProtocol.getProtocol();
        this.fullMessage = callbacks.saveBuffersToTempFiles(ssoProtocol.getMessage());
        this.host = helpers.analyzeRequest(this.fullMessage ).getUrl().getHost();
        this.method = helpers.analyzeRequest(this.fullMessage ).getMethod();
        this.url = helpers.analyzeRequest(this.fullMessage ).getUrl().getPath();
        this.token = ssoProtocol.getToken();
        LocalTime t = LocalTime.now();
        this.timestamp = t;
        this.time = t.toString().substring(0, t.toString().length()-4);
        this.length = (new Integer(this.fullMessage.getResponse().length)).toString();
        this.comment = this.fullMessage .getComment();
        this.ssoProtocol = ssoProtocol;
    }

    //Getter

    /**
     * Get the index of the message.
     * @return The count.
     */
        public Integer getCounter() {
        return counter;
    }

    /**
     * Get the protocol name.
     * @return The protocol name.
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Get the http host.
     * @return The http host.
     */
    public String getHost() {
        return host;
    }

    /**
     * Get the http method.
     * GET / POST / PUT/ DELETE ...
     * @return The http method.
     */
    public String getMethod() {
        return method;
    }
    
    /**
     * Get the URL.
     * Its the path of the host.
     * @return Get the path.
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the length of the request.
     * @return The length.
     */
    public String getLength() {
        return length;
    }

    /**
     * Get the token.
     * @return The token.
     */
    public String getToken() {
        return token;
    }

    /**
     * Get the Time.
     * The time is computed from the timestamp.
     * @return The time (XX:XX:XX).
     */
    public String getTime() {
        return time;
    }
    
    /**
     * Get the comment.
     * Stores additional data for the protocol
     * @return The comment.
     */
    public String getComment() {
        return comment;
    }

    /**
     * Get the http message.
     * @return The http message.
     */
    public IHttpRequestResponsePersisted getMessage() {
        return fullMessage;
    }
    
    /**
     * Get the protocol flow.
     * @return The protocol flow.
     */
    public ArrayList<SSOProtocol> getProtocolFlow(){
        return ssoProtocol.getProtocolFlow();
    }
    
    /**
     * Get the {@link SSOProtocol}.
     * @return The {@link SSOProtocol}
     */
    public SSOProtocol getSSOProtocol(){
        return ssoProtocol;
    }
    
    /**
     * Get the timestamp.
     * @return {@link java.time.LocalTime}
     */
    public LocalTime getTimestamp(){
        return timestamp;
    }

    //Setter

    /**
     * Set the comment.
     * @param comment The comment.
     */
        public void setComment(String comment) {
        this.comment = comment;
    }
    
    /**
     * Set the index of the entry.
     * @param i The index.
     */
    public void setCounter(int i){
        this.counter = (new Integer(i));
    }
}
