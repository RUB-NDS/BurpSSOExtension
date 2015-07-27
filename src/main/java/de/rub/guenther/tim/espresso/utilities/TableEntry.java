/*
 * Copyright (C) 2015 Tim Guenther
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111null307, USA.
 */
package de.rub.guenther.tim.espresso.utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponsePersisted;
import java.time.LocalTime;

/**
 *
 * @author Tim Guenther
 */
public class TableEntry {
    private String counter = "";
    private String number = "";
    private String protocol = "";
    private String host = "";
    private String method = "";
    private String url = "";
    private String token = "";
    private String time = "";
    private String length = "";
    private String comment = "";
    private IHttpRequestResponsePersisted fullMessage = null;

    //Constructor
    public TableEntry(String counter, String number, String protocol, String token, IHttpRequestResponsePersisted messageInfo, IBurpExtenderCallbacks callbacks) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        
        this.counter = counter;
        this.number = number;
        this.protocol = protocol;
        this.host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
        this.method = helpers.analyzeRequest(messageInfo).getMethod();
        this.url = helpers.analyzeRequest(messageInfo).getUrl().getPath();
        this.token = token;
        LocalTime t = LocalTime.now();
        this.time = t.toString();
        this.length = (new Integer(messageInfo.getResponse().length)).toString();
        this.comment = messageInfo.getComment();
        this.fullMessage = messageInfo;
    }

    //Getter
    public String getCounter() {
        return counter;
    }

    public String getNumber() {
        return number;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getHost() {
        return host;
    }

    public String getMethod() {
        return method;
    }
    
    public String getUrl() {
        return url;
    }

    public String getLength() {
        return length;
    }

    public String getToken() {
        return token;
    }

    public String getTime() {
        return time;
    }
    
    public String getComment() {
        return comment;
    }

    public IHttpRequestResponsePersisted getFullMessage() {
        return fullMessage;
    }
    
    

    //Setter
    public void setComment(String comment) {
        this.comment = comment;
    }
    
    
    
    
    
}
