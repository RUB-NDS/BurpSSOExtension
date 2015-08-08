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
package de.rub.nds.burp.espresso.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import de.rub.nds.burp.espresso.gui.UITab;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import de.rub.nds.burp.utilities.table.TableDB;
import de.rub.nds.burp.utilities.table.TableEntry;
import de.rub.nds.burp.utilities.protocols.SAML;
import java.io.PrintWriter;
import java.util.List;

/**
 * Scan for Single Sign-On protocols in requests.
 * @author Tim Guenther
 * @version 1.0
 */
public class SSOScanner implements IHttpListener{
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stderr;
    private UITab tab;
    private IHttpRequestResponse messageInfo;
    
    private static int counter = 0;
    private static int number = 0;
    
    /**
     * Create a new SSOScanner.
     * @param callbacks Provided by the Burp Suite api.
     * @param tab A tab for the Burp Suite GUI.
     */
    public SSOScanner(IBurpExtenderCallbacks callbacks, UITab tab) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.tab = tab;
    }

    /**
    * Implementation of the IHttpListener interface.
    * Is called every time a request/response is processed by Burp Suite.
    * @param toolFlag A numeric identifier for the Burp Suite tool that calls. 
    * @param isRequest True for a request, false for a response.
    * @param httpRequestResponse The request/response that should processed.
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse httpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !isRequest) {
            
            //num.,protoc.,token
            String[] npt = checkForProtocol(httpRequestResponse);
            if(npt != null){
                String count = Integer.toString(++counter);
                String num = "NaN";
                String protocol = npt[0];
                String token = npt[1];

                TableEntry e = new TableEntry(count,num,protocol,token,callbacks.saveBuffersToTempFiles(httpRequestResponse),callbacks);
                
                //add new tab/table to history
                if(protocol.equals("SAML")){
                    if(tab.getUiMain().getHistory().addNewTable(protocol+token)){
                        try {
                            //a little race condition with the new tab
                            Thread.sleep(500);
                        } catch (InterruptedException ex) {
                            stderr.println("Sleep: "+ex.toString());
                        }
                    }
                    //add new entry to new 
                    TableDB.getTable(protocol+token).getTableHelper().addRow(e);
                }

                //Full History
                TableDB.getTable(0).getTableHelper().addRow(e);
            }
        }
    }
    
    private String[] checkForProtocol(IHttpRequestResponse messageInfo){
        this.messageInfo = messageInfo;
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        final List<IParameter> parameterList = requestInfo.getParameters();
        String[] npt = {"",""}; 

        for(IParameter param : parameterList){
            switch(param.getName()){
                case SSOProtocol.SAML_REQUEST:
                    npt = makeSAML(param);
                    break;
                case SSOProtocol.SAML_RESPONSE:
                    npt = makeSAML(param);
                    break;
                default:
            }
        }
        //checkRequestForOpenId(requestInfo, messageInfo);
        //checkRequestHasOAuthParameters(requestInfo, messageInfo);
        // checkRequestForBrowserId(requestInfo, messageInfo);
        return npt;
    }
    
    private String[] makeSAML(IParameter param){
        SAML saml = new SAML();
        if(param.getName().equals(SSOProtocol.SAML_REQUEST)){
            saml = new SAML(param, callbacks);
        } else if(param.getName().equals(SSOProtocol.SAML_RESPONSE)){
            saml = new SAML(helpers.getRequestParameter(messageInfo.getRequest(), SSOProtocol.SAML_RESPONSE), callbacks);
        }
        if(saml.getID() != null){
            String[] res = {"SAML",saml.getID()};
            return res;
        }
        return null;
    }
}
