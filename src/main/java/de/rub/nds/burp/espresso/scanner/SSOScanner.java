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
import de.rub.nds.burp.espresso.gui.UIOptions;
import de.rub.nds.burp.espresso.gui.UITab;
import static de.rub.nds.burp.utilities.ParameterUtilities.parameterListContainsParameterName;
import de.rub.nds.burp.utilities.protocols.BrowserID;
import de.rub.nds.burp.utilities.protocols.OAuth;
import de.rub.nds.burp.utilities.protocols.OpenID;
import de.rub.nds.burp.utilities.protocols.OpenIDConnect;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import de.rub.nds.burp.utilities.table.TableDB;
import de.rub.nds.burp.utilities.table.TableEntry;
import de.rub.nds.burp.utilities.protocols.SAML;
import de.rub.nds.burp.utilities.table.Table;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
                String protocol = npt[0];
                String token = npt[1];

                TableEntry e = new TableEntry(count,protocol,token,callbacks.saveBuffersToTempFiles(httpRequestResponse),callbacks);

                //Full History
                TableDB.getTable(0).getTableHelper().addRow(e);
                //Add content to additional tables
                for(int i = 1; i<TableDB.size(); i++){
                    Table t = TableDB.getTable(i);
                    if(token.equals(t.getID())){
                        t.getTableHelper().addRow(e);
                    }
                }
            }
        }
    }
    
    private String[] checkForProtocol(IHttpRequestResponse messageInfo){
        this.messageInfo = messageInfo;
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        final List<IParameter> parameterList = requestInfo.getParameters();
        String[] npt = null; 

        for(IParameter param : parameterList){
            if(UIOptions.samlActive){
                npt = checkForSAML(param);
                if(npt != null){
                    break;   
                }
            }
            if(UIOptions.openIDActive){
                npt = checkForOpenID(param, parameterList);
                if(npt != null){
                    break;   
                }
            }
            if(false){//if(UIOptions.openIDConnectBool){
                npt = checkForSAML(param);
                if(npt != null){
                    break;   
                }
            }
            if(false){//if(UIOptions.oAuthv2Bool){;
                npt = checkForSAML(param);
                if(npt != null){
                    break;   
                }
            }
        }
        if(UIOptions.browserIDActive && npt == null){
            npt = checkForBrowserID(parameterList);
        }
        if(UIOptions.oAuthv1Active && npt == null){
            npt = checkForOAuth(parameterList);
        }
        return npt;
    }
    
    private String[] makeSAML(IParameter param){
        SAML saml = null;
        if(param.getName().equals(SSOProtocol.SAML_REQUEST)){
            saml = new SAML(param, callbacks);
        } else if(param.getName().equals(SSOProtocol.SAML_RESPONSE)){
            saml = new SAML(helpers.getRequestParameter(messageInfo.getRequest(), SSOProtocol.SAML_RESPONSE), callbacks);
        } else if( param.getName().equals(SSOProtocol.SAML_RELAYSTATE) || param.getName().equals(SSOProtocol.SAML_ARTIFACT)){
            saml = new SAML(param, callbacks);
        }
        if(saml.getToken() != null){
            String[] res = {"SAML",saml.getToken()};
            return res;
        }
        return null;
    }
    
    private String[] makeOpenID(IParameter param, String protocol){
        new PrintWriter(callbacks.getStderr(), true).println(protocol);
        OpenID openId = new OpenID(param, callbacks, protocol, messageInfo);
        String[] res = {protocol, openId.getToken()};
        return res;
    }
    
    private String[] makeOpenIDConnect(IParameter param, String protocol){
        OpenIDConnect openIdConnect = new OpenIDConnect(param, callbacks, messageInfo);
        String[] res = {protocol, openIdConnect.getToken()};
        return res;
    }
    
    private String[] makeOAuth(IParameter param){
        OAuth oAuth = new OAuth(param, callbacks, messageInfo);
        String[] res = {SSOProtocol.OAUTH_V2, oAuth.getToken()};
        return res;
    }
    
    private String[] makeBrowserID(List<IParameter> parameterList){
        BrowserID browserId = new BrowserID(parameterList, callbacks, messageInfo);
        String[] res = {SSOProtocol.BROWSERID, browserId.getToken()};
        return res;
    }
    
    private String[] checkForSAML(IParameter param){
        String[] npt = null; 
        switch(param.getName()){
            case SSOProtocol.SAML_REQUEST:
                npt = makeSAML(param);
                break;
            case SSOProtocol.SAML_RESPONSE:
                npt = makeSAML(param);
                break;
            default:
        }
        return npt;
    }
    
    //TODO: Implement protocol.
    private String[] checkForOpenID(IParameter param, List<IParameter> paramList){
        String[] npt = null;
        Set<String> IN_REQUEST_OPENID2 = new HashSet<String>(Arrays.asList(
		new String[]{"openid.claimed_id", "openid.op_endpoint"}
	));
        String protocol = SSOProtocol.OPENID_V1;
        if(parameterListContainsParameterName(paramList, IN_REQUEST_OPENID2)){
            protocol = SSOProtocol.OPENID_V2;
        }
        if(param.getName().equals(SSOProtocol.OPENID_PARAM)){
            switch (param.getValue()) {
                case SSOProtocol.OPENID_REQUEST:
                    npt = makeOpenID(param, protocol);
                    break;
                case SSOProtocol.OPENID_RESPONSE:
                    npt = makeOpenID(param, protocol);
                    break;
            }
        }
        return npt;
    }
    
    //TODO: Implement protocol.
    private String[] checkForOpenIdConnect(IParameter param){
        String[] npt = null; ;
        npt = makeOpenIDConnect(param, "OpenID Connect");
        return npt;
    }
    
    //TODO: Implement protocol.
    private String[] checkForOAuth(List<IParameter> paramList){
        Set<String> IN_REQUEST_OAUTH_TOKEN_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[]{"redirect_uri", "scope", "client_id"}
	));
        String[] npt = null; 
        if(parameterListContainsParameterName(paramList, IN_REQUEST_OAUTH_TOKEN_PARAMETER)){
            npt = makeOAuth(paramList.get(0));
        }
        return npt;
    }
    
    //TODO: Implement protocol.
    private String[] checkForOAuthv2(IParameter param){
        String[] npt = null; 
        switch(param.getName()){
            case SSOProtocol.SAML_REQUEST:
                npt = makeSAML(param);
                break;
            case SSOProtocol.SAML_RESPONSE:
                npt = makeSAML(param);
                break;
            default:
        }
        return npt;
    }
    
    //TODO: Implement protocol.
    private String[] checkForBrowserID(List<IParameter> parameterList){
        String[] npt = null;
        Set<String> IN_REQUEST_BROWSERID_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[]{"browserid_state", "assertion"}
	));
        if(parameterListContainsParameterName(parameterList, IN_REQUEST_BROWSERID_PARAMETER)){
            npt = makeBrowserID(parameterList);
        }
        return npt;
    }
}
