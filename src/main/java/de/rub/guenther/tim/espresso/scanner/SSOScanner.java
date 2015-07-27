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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package de.rub.guenther.tim.espresso.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import de.rub.guenther.tim.espresso.gui.UITab;
import de.rub.guenther.tim.espresso.utilities.TableDB;
import de.rub.guenther.tim.espresso.utilities.TableEntry;
import de.rub.guenther.tim.espresso.utilities.protocols.SAML;
import static de.rub.nds.burp.utilities.ParameterUtilities.parameterListContainsParameterName;
import java.io.PrintWriter;
import java.util.List;

/**
 *
 * @author Tim Guenther
 */
public class SSOScanner implements IHttpListener{
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stderr;
    private UITab tab;
    
    private static int counter = 0;
    private static int number = 0;

    public SSOScanner(IBurpExtenderCallbacks callbacks, UITab tab) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.tab = tab;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            
            //num.,protoc.,token
            String[] npt = checkForProtocol(messageInfo);
            if(npt != null){
                String count = Integer.toString(++counter);
                String num = "NaN";
                String protocol = npt[0];
                String token = npt[1];

                TableEntry e = new TableEntry(count,num,protocol,token,callbacks.saveBuffersToTempFiles(messageInfo),callbacks);
                
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
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        final List<IParameter> parameterList = requestInfo.getParameters();
        String[] npt = {"",""}; 

        if(true){
            npt[0] = "SAML";
            SAML saml = new SAML();
            for(IParameter param : parameterList){
                switch(param.getName()){
                    case "SAMLRequest":
                        saml = new SAML(param, callbacks);
                        stderr.println(saml.toString());
                        break;
                    case "SAMLResponse":
                        saml = new SAML(helpers.getRequestParameter(messageInfo.getRequest(), "SAMLResponse"), callbacks);
                        stderr.println(saml.toString());
                        break;
                    default:
                }
            }
            if(saml.getID() != null){
                npt[1] = saml.getID();
                return npt;
            }
        }
        //checkRequestForOpenId(requestInfo, messageInfo);
        //checkRequestHasOAuthParameters(requestInfo, messageInfo);
        // checkRequestForBrowserId(requestInfo, messageInfo);
        return null;
    }
}
