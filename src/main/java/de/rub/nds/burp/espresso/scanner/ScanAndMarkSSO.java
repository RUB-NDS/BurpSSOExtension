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
package de.rub.nds.burp.espresso.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import de.rub.nds.burp.espresso.gui.UIOptions;
import de.rub.nds.burp.utilities.Logging;
import static de.rub.nds.burp.utilities.ParameterUtilities.getFirstParameterByName;
import static de.rub.nds.burp.utilities.ParameterUtilities.parameterListContainsParameterName;
import de.rub.nds.burp.utilities.protocols.BrowserID;
import de.rub.nds.burp.utilities.protocols.FacebookConnect;
import de.rub.nds.burp.utilities.protocols.MicrosoftAccount;
import de.rub.nds.burp.utilities.protocols.OAuth;
import de.rub.nds.burp.utilities.protocols.OpenID;
import de.rub.nds.burp.utilities.protocols.OpenIDConnect;
import de.rub.nds.burp.utilities.protocols.SAML;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import de.rub.nds.burp.utilities.table.Table;
import de.rub.nds.burp.utilities.table.TableDB;
import de.rub.nds.burp.utilities.table.TableEntry;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Highlight request in the proxy history.
 * The protocols OpenID, OpenID Connect, OAuth, BrowserID and SAML are highlighted.
 * @author Christian Mainka, Tim Guenther
 * @version 1.0
 */

public class ScanAndMarkSSO implements IHttpListener {
    
        private IHttpRequestResponse prev_message = null;
        private boolean oauth_code_requested = false;
    
        private static int counter = 1;
        
	private static final Set<String> IN_REQUEST_OAUTH_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"redirect_uri", "scope", "client_id", "client_secret",  "response_type"}
	));
        private static final Set<String> IN_REQUEST_OAUTH_AUTH_CODE_GRANT_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"grant_type", "response_type"}
	));
        private static final Set<String> IN_REQUEST_OAUTH_IMPLICIT_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"access_token", "response_type"}
	));

	private static final Set<String> IN_REQUEST_SAML_TOKEN_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"SAMLResponse"}
	));

	private static final Set<String> IN_REQUEST_SAML_REQUEST_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"SAMLRequest"}
	));

	private static final Set<String> IN_REQUEST_BROWSERID_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"browserid_state", "assertion"}
	));
        
        private static final Set<String> IN_REQUEST_FACEBOOKCONNECT_PARAMETER = new HashSet<String>(Arrays.asList(
            new String[]{"app_id", "domain", "origin",  "sdk"}
	));
        
        //Monolitic protocol hosts
        private final String FBC_HOST = "facebook.com";
        private final String MSA_HOST = "live.com";
        private final String MSA_HOST2 = "live.net";
        private final String MSA_HOST3 = "contoso.com";
        private final String BID_HOST = "persona.org";

	private static final String HIGHLIGHT_COLOR = "yellow";
	private static final String MIMETYPE_HTML = "HTML";
	private static final int STATUS_OK = 200;

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
        
        /**
         * Create a new HttpMarker.
         * @param callbacks IPC for the Burp Suite api.
         */
	public ScanAndMarkSSO(IBurpExtenderCallbacks callbacks) {
            this.callbacks = callbacks;
            this.helpers = callbacks.getHelpers();
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
            // only flag messages sent/received by the proxy
            if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !isRequest) {
                    TableEntry entry = processSSOScan(httpRequestResponse);
                    if(entry != null){
                        updateTables(entry);
                    }
                    
                    processLoginPossibilities(httpRequestResponse);
                    prev_message = httpRequestResponse;
            }
	}

	private void processLoginPossibilities(IHttpRequestResponse httpRequestResponse) {
            final byte[] responseBytes = httpRequestResponse.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            checkRequestForOpenIdLoginMetadata(responseInfo, httpRequestResponse);
	}

	private TableEntry processSSOScan(IHttpRequestResponse httpRequestResponse) {
            IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
            String host = requestInfo.getUrl().getHost();
            //The order is very important!
            if(UIOptions.isFBConnectActive()){
                if(host.contains(FBC_HOST)){
                    SSOProtocol protocol = checkRequestForFacebookConnect(requestInfo, httpRequestResponse);
                    if(protocol != null){
                        protocol.setCounter(counter++);
                        return protocol.toTableEntry();
                    }
                }
            }
            if(UIOptions.isMSAccountActive()){
                if(host.contains(MSA_HOST) || host.contains(MSA_HOST2) || host.contains(MSA_HOST3)){
                    SSOProtocol protocol = checkRequestForMicrosoftAccount(requestInfo, httpRequestResponse);
                    if(protocol != null){
                        protocol.setCounter(counter++);
                        return protocol.toTableEntry();
                    }
                }
            }
            if(UIOptions.isOpenIDConnectActive()){
                //Exclude all monolithic protocols
                if(!host.contains(FBC_HOST) || !host.contains(MSA_HOST) || !host.contains(MSA_HOST2) || !host.contains(MSA_HOST3) || !host.contains(BID_HOST)){
                    SSOProtocol protocol = checkRequestForOpenIdConnect(requestInfo, httpRequestResponse);
                    if(protocol != null){
                        protocol.setCounter(counter++);
                        return protocol.toTableEntry();
                    }
                }
            }
            if(UIOptions.isOAuthActive()){
                //Exclude all monolithic protocols
                if(!host.contains(FBC_HOST) || !host.contains(MSA_HOST) || !host.contains(BID_HOST)){
                    SSOProtocol protocol = checkRequestForOAuth(requestInfo, httpRequestResponse);
                    if(protocol != null){
                        protocol.setCounter(counter++);
                        return protocol.toTableEntry();
                    }
                }
            }
            if(UIOptions.isOpenIDActive()){
                SSOProtocol protocol = checkRequestForOpenId(requestInfo, httpRequestResponse);
                if(protocol != null){
                    protocol.setCounter(counter++);
                    return protocol.toTableEntry();
                }
            }
            if(UIOptions.isSamlActive()){
                SSOProtocol protocol = checkRequestForSaml(requestInfo, httpRequestResponse);
                if(protocol != null){
                    protocol.setCounter(counter++);
                    return protocol.toTableEntry();
                }
            }
            if(UIOptions.isBrowserIDActive()){
                SSOProtocol protocol = checkRequestForBrowserId(requestInfo, httpRequestResponse);
                if(protocol != null){
                    protocol.setCounter(counter++);
                    return protocol.toTableEntry();
                }
            }
            return null;
	}
        
        private void updateTables(TableEntry entry){
            //Full history
            TableDB.getTable(0).getTableHelper().addRow(entry);
            //Add content to additional tables
            for(int i = 1; i<TableDB.size(); i++){
                Table t = TableDB.getTable(i);
                t.update();
            }
        }
        
        private SSOProtocol checkRequestForOpenIdConnect(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            final List<IParameter> parameterList = requestInfo.getParameters();
            String request = helpers.bytesToString(httpRequestResponse.getRequest());
            String response = helpers.bytesToString(httpRequestResponse.getResponse());
            OpenIDConnect oidc = null;
            String comment = "";
            if(null != prev_message){
                 //Check for Hybird Flow
                if(oidc == null){
                    IParameter response_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                    if(response_type != null){
                        String response_type_value = response_type.getValue();
                        if(response_type_value.contains("code")){
                            if(response_type_value.contains("id_token")){
                                Logging.getInstance().log(getClass(), "9", Logging.DEBUG);
                                comment = "OpenID Connect Hybrid Flow";
                                markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                                oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                            } else if(response_type_value.contains("token")){
                                Logging.getInstance().log(getClass(), "10", Logging.DEBUG);
                                comment = "OpenID Connect Hybrid Flow";
                                markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                                oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                            }
                            //Classification for code, id_token, token is also covered with the code above.
                        }
                    }
                }
                
                //Mark the redirect message;
                IResponseInfo prev_responseInfo = helpers.analyzeResponse(prev_message.getResponse());
                //Check for OpenID Connect Authorization Code Flow Request
                if(helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() == 302 && oidc == null){
                    //302 Authorisation Code FLow
                    Pattern p1 = Pattern.compile("^Location:.*?response_type=code.*?$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                    Pattern p2 = Pattern.compile("^Location:.*?&?scope=[a-zA-Z+]*?openid[a-zA-Z+]*?&?.*?$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                    Matcher m1 = p1.matcher(response);
                    Matcher m2 = p2.matcher(response);
                    if(m1.find() && m2.find()){
                        Logging.getInstance().log(getClass(), "1", Logging.DEBUG);
                        comment = "OpenID Connect ACF Request";
                        markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                        oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                    }
                    
                    //302 Implicit Flow
                    IParameter response_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                    if(response_type != null){
                        String response_type_value = response_type.getValue();
                        if(null == oidc && response_type_value.contains("id_token")){
                            comment = "OpenID Connect Implicit Flow Request";
                            markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                            oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                        }
                    }
                }
                
                //Mark the actual message
                if(prev_responseInfo.getStatusCode() == 302 && oidc == null){
                    //Authorisation Code Flow
                    IParameter response_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                    IParameter pre_response_type = helpers.getRequestParameter(prev_message.getRequest(), "response_type");
                    if(response_type != null && pre_response_type != null){
                        if(response_type.getValue().contains("code") && pre_response_type.getValue().contains("code")){
                            IParameter scope = helpers.getRequestParameter(httpRequestResponse.getRequest(), "scope");
                            IParameter pre_scope = helpers.getRequestParameter(prev_message.getRequest(), "scope");

                            if(scope != null && pre_scope != null){
                                if(scope.getValue().contains("openid") && pre_scope.getValue().contains("openid")){
                                    Logging.getInstance().log(getClass(), "4", Logging.DEBUG);
                                    comment = "OpenID Connect ACF Request";
                                    markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                                    oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                                }

                            } else if(scope != null){
                                if(scope.getValue().contains("openid")){
                                    Logging.getInstance().log(getClass(), "5", Logging.DEBUG);
                                    comment = "OpenID Connect";
                                    markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                                    oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                                }
                            }
                        }
                    }
                    
                    //Implicit Flow
                    if(oidc == null){
                        
                        if(null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "id_token")){
                            Logging.getInstance().log(getClass(), "7", Logging.DEBUG);
                            comment = "OpenID Connect Implicit Flow Response";
                            markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                            oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                            
                        } else if(null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "access_token")){
                            Logging.getInstance().log(getClass(), "8", Logging.DEBUG);
                            comment = "OpenID Connect Implicit Flow Access Token";
                            markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                            oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                        }
                    }
                }
            }
            //Check for Discovery Flow
            if(oidc == null){
                Pattern p1 = Pattern.compile("\\/\\.well-known\\/openid-configuration|\\/\\.well-known\\/webfinger", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                Matcher m1 = p1.matcher(request);
                if(m1.find()){
                    Logging.getInstance().log(getClass(), "13", Logging.DEBUG);
                    comment = "OpenID Connect Discovery Flow";
                    markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                    oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                }
            }
            
            //Generic detection
            IParameter code = helpers.getRequestParameter(httpRequestResponse.getRequest(), "code");
            IParameter scope = helpers.getRequestParameter(httpRequestResponse.getRequest(), "scope");
            IParameter state = helpers.getRequestParameter(httpRequestResponse.getRequest(), "state");
            if((code != null | state != null) && oidc == null && scope != null){
                if(scope.getValue().contains("openid")){
                    Logging.getInstance().log(getClass(), "6", Logging.DEBUG);
                    comment = "OpenID Connect";
                    markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                    oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect", callbacks);
                } else {
                    Logging.getInstance().log(getClass(), "6", Logging.DEBUG);
                    comment = "OpenID Connect / OAuth";
                    markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
                    oidc = new OpenIDConnect(httpRequestResponse, "OpenID Connect / OAuth", callbacks);
                }
            }
            return oidc;
	}
        
        private SSOProtocol checkRequestForFacebookConnect(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            String comment = "";
            FacebookConnect fbc = null;
            if((requestInfo.getUrl().toString()).contains("/ping?")){
                comment = "Facebook Connect Ping Request";
                fbc = new FacebookConnect(httpRequestResponse, "Facebook Connect", callbacks);
            }
            
            if(parameterListContainsParameterName(requestInfo.getParameters(), IN_REQUEST_FACEBOOKCONNECT_PARAMETER) && comment.equals("")){
                comment = "Facebook Connect";
                fbc = new FacebookConnect(httpRequestResponse, "Facebook Connect", callbacks);
            } else {
                SSOProtocol possible_oauth = checkRequestForOAuth(requestInfo,httpRequestResponse);
                if(null != possible_oauth && fbc == null){
                    comment = "Facebook Connect OAuth";
                    fbc = new FacebookConnect(httpRequestResponse, "Facebook Connect", callbacks);
                }
            }
            
            if(null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "signed_request")){
                if(comment.equals("")){
                    comment = "Facebook Connect Authentication Response";
                    fbc = new FacebookConnect(httpRequestResponse, "Facebook Connect", callbacks);
                } else {
                    comment += ", FBC Authentication Response";
                }
            }
            if(null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type")){
                IParameter respose_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                if(respose_type.getValue().contains("signed_request")){
                    if(comment.equals("")){
                        comment = "Facebook Connect Authentication Request";
                        fbc = new FacebookConnect(httpRequestResponse, "Facebook Connect", callbacks);
                    } else {
                        comment += ", FBC Authentication Request";
                    }
                }
            }

            if(fbc != null && !comment.equals("")){
                markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
            }
            return fbc;
        }
        
        private SSOProtocol checkRequestForMicrosoftAccount(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            String comment = "";
            MicrosoftAccount msa = null;
            IParameter scope = helpers.getRequestParameter(httpRequestResponse.getRequest(), "scope");
            if(scope != null){
                String scope_value = scope.getValue();
                Pattern p = Pattern.compile("wl\\.basic|wl\\.offline_access|wl\\.signin");
                Matcher m = p. matcher(scope_value);
                if(m.find()){
                    comment = "Microsoft Account with OAuth";
                    msa = new MicrosoftAccount(httpRequestResponse, "Microsoft Account", callbacks);
                }
                if(scope_value.contains("openid")){
                    SSOProtocol possible_oidc = checkRequestForOpenIdConnect(requestInfo, httpRequestResponse);
                    if(possible_oidc != null){
                        comment = "Micrsoft Account";
                        msa = new MicrosoftAccount(httpRequestResponse, "Microsoft Account", callbacks);
                    }
                }
            }
            
            if(msa == null){
                IParameter wa = helpers.getRequestParameter(httpRequestResponse.getRequest(), "wa");
                if(wa != null){
                    if(wa.getValue().equals("wsignin1.0")){
                        comment = "Microsoft Account with WS-Federation";
                        msa = new MicrosoftAccount(httpRequestResponse, "Microsoft Account", callbacks);
                    }
                } else {
                    SSOProtocol possible_oauth = checkRequestForOAuth(requestInfo,httpRequestResponse);
                    if(null != possible_oauth && msa == null){
                        comment = "Microsoft Account";
                        msa = new MicrosoftAccount(httpRequestResponse, "Microsoft Account", callbacks);
                    }
                }
            }
            
            if(msa != null){
                markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
            }
            return msa;
        }

	private SSOProtocol checkRequestForOpenId(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            final List<IParameter> parameterList = requestInfo.getParameters();
            IParameter openidMode = getFirstParameterByName(parameterList, "openid.mode");
            String protocol = "OpenID";
            if (openidMode != null) {
                if(openidMode.getValue().contains("checkid_setup")) {
                    markRequestResponse(httpRequestResponse, "OpenID Request", HIGHLIGHT_COLOR);
                }  else if(openidMode.getValue().equals("associate")){
                    markRequestResponse(httpRequestResponse, "OpenID Association", HIGHLIGHT_COLOR);
                    
                } else if(null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "openid.sig")){
                    
                    if (null != helpers.getRequestParameter(httpRequestResponse.getRequest(), "openid.claimed_id")) {
                            markRequestResponse(httpRequestResponse, "OpenID 2.0 Token", HIGHLIGHT_COLOR);
                            protocol += " v2.0";
                    } else {
                            markRequestResponse(httpRequestResponse, "OpenID 1.0 Token", HIGHLIGHT_COLOR);
                            protocol += " v1.0";
                    }
                }
                
                return new OpenID(httpRequestResponse, protocol, callbacks);
            }
            return null;
	}

	private SSOProtocol checkRequestForOAuth(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            OAuth oauth = null;
            String comment = null;
            if (parameterListContainsParameterName(requestInfo.getParameters(), IN_REQUEST_OAUTH_PARAMETER)) {
                oauth =  new OAuth(httpRequestResponse, "OAuth", callbacks);
                
                //Code Flow
                if(parameterListContainsParameterName(requestInfo.getParameters(), IN_REQUEST_OAUTH_AUTH_CODE_GRANT_PARAMETER)){
                    
                    if(null != prev_message){
                        IResponseInfo prev_responseInfo = helpers.analyzeResponse(prev_message.getResponse());
                        //Check for OAuth Authorization Code Grant Request
                        if(prev_responseInfo.getStatusCode() == 302){
                            IParameter response_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                            IParameter pre_response_type = helpers.getRequestParameter(prev_message.getRequest(), "response_type");
                            if(response_type != null && pre_response_type != null){
                                if(response_type.getValue().contains("code") && pre_response_type.getValue().contains("code")){
                                    comment = "OAuth ACG Request";
                                    oauth_code_requested = true;
                                } else {

                                    // Check for OAuth Authorization Code Grant Code
                                    IParameter code = helpers.getRequestParameter(httpRequestResponse.getRequest(), "code");
                                    if(code != null && oauth_code_requested && comment == null){
                                        comment = "OAuth ACG Code";
                                        oauth_code_requested = false;
                                    }

                                    //Check for OAuth Authorization Code Grant Token Request
                                    IParameter grant_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "grant_type");
                                    if(grant_type != null && comment == null){
                                        if(grant_type.getValue().contains("auth_code")){
                                            comment = "OAuth ACG Token Request";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                //Implicit Flow     
                } else if(parameterListContainsParameterName(requestInfo.getParameters(), IN_REQUEST_OAUTH_IMPLICIT_PARAMETER) && comment == null){
                    if(null != prev_message){
                        IResponseInfo prev_responseInfo = helpers.analyzeResponse(prev_message.getResponse());
                        //Check for OAuth Implicit Grant Request
                        if(prev_responseInfo.getStatusCode() == 302){
                            IParameter response_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "response_type");
                            IParameter pre_response_type = helpers.getRequestParameter(prev_message.getRequest(), "response_type");
                            
                            if(response_type.getValue().contains("token") && pre_response_type.getValue().contains("token")){
                                comment = "OAuth Implicit Grant Request";
                                oauth_code_requested = true;
                            }
                        }
                    }
                    
                    // Check for OAuth Implicit Token
                    if(helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() == 302 && comment == null){
                        String response = helpers.bytesToString(httpRequestResponse.getResponse());
                        // Check for OAuth Implicit Token
                        Pattern p = Pattern.compile("Location:.*?#.*?access_token=.*?&?", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                        Matcher m = p.matcher(response);
                        if(m.find()){
                            comment = "OAuth Implicit Token";
                            oauth_code_requested = false;
                        }
                    } else if(comment == null){
                        comment = "OAuth (IF)";
                    }
                }
                
                 if(comment == null){
                    //Check for other OAuth flows
                    IParameter grant_type = helpers.getRequestParameter(httpRequestResponse.getRequest(), "grant_type");
                    if(grant_type != null){
                        switch(grant_type.getValue()){
                            case "authorization_code":
                                comment = "OAuth Access Token Request";
                                break;
                            case "refresh_token":
                                comment = "OAuth Refresh Token Request";
                                break;
                            case "password":
                                comment = "OAuth Resource Owner Password Credentials Grant";
                                break;
                            case "client_credentials":
                                comment = "OAuth Client Credentials Grant";
                                break;
                            case "urn:ietf:params:oauth:grant-type:jwt-bearer":
                                comment = "OAuth Extension JWT Grant";
                                break;
                            case "urn:oasis:names:tc:SAML:2.0:cm:bearer":
                                comment = "OAuth Extension SAML Grant";
                                break;
                            default:
                                comment = "OAuth ACGF";
                        }
                    }
                }
                
                if(comment == null){
                    comment = "OAuth";
                }
                markRequestResponse(httpRequestResponse, comment, HIGHLIGHT_COLOR);
            }
            return oauth;
	}

	private SSOProtocol checkRequestForSaml(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            final List<IParameter> parameterList = requestInfo.getParameters();
            if (parameterListContainsParameterName(parameterList, IN_REQUEST_SAML_REQUEST_PARAMETER)) {
                markRequestResponse(httpRequestResponse, "SAML Authentication Request", HIGHLIGHT_COLOR);
                return new SAML(httpRequestResponse, "SAML", callbacks, getFirstParameterByName(parameterList, "SAMLRequest"));
            }

            if (parameterListContainsParameterName(parameterList, IN_REQUEST_SAML_TOKEN_PARAMETER)) {
                markRequestResponse(httpRequestResponse, "SAML Response Token", HIGHLIGHT_COLOR);
                return new SAML(httpRequestResponse, "SAML", callbacks, getFirstParameterByName(parameterList, "SAMLResponse"));
            }
            return null;
	}

	private boolean checkRequestForOpenIdLoginMetadata(IResponseInfo responseInfo, IHttpRequestResponse httpRequestResponse) {
            if (responseInfo.getStatusCode() == STATUS_OK && MIMETYPE_HTML.equals(responseInfo.getStatedMimeType())) {
                final byte[] responseBytes = httpRequestResponse.getResponse();
                final int bodyOffset = responseInfo.getBodyOffset();
		final String responseBody = (new String(responseBytes)).substring(bodyOffset);
                final String response = helpers.bytesToString(responseBytes);
                final String request = helpers.bytesToString(httpRequestResponse.getResponse());
                
                Pattern p = Pattern.compile("=[\"'][^\"']*openid[^\"']*[\"']", Pattern.CASE_INSENSITIVE);
                Matcher m = p.matcher(responseBody);
                if (m.find()) {
                    markRequestResponse(httpRequestResponse, "OpenID Login Possibility", "green");
                    IRequestInfo iri = helpers.analyzeRequest(httpRequestResponse);
                    callbacks.issueAlert("OpenID Login on: "+iri.getUrl().toString()); 
                    return true;
                }
                p = Pattern.compile("rel=\"openid(.server|.delegate|2.provider|2.local_id)\"", Pattern.CASE_INSENSITIVE);
                m = p.matcher(responseBody);
                if (m.find()) {
                    markRequestResponse(httpRequestResponse, "OpenID Metadata", "green");
                    IRequestInfo iri = helpers.analyzeRequest(httpRequestResponse);
                    callbacks.issueAlert("OpenID Login on: "+iri.getUrl().toString());
                    return true;
                }
                p = Pattern.compile("openid(.server|.delegate|2.provider|2.local_id|.click)", Pattern.CASE_INSENSITIVE);
                m = p.matcher(request);
                if (m.find()) {
                    markRequestResponse(httpRequestResponse, "OpenID Metadata", "green");
                    IRequestInfo iri = helpers.analyzeRequest(httpRequestResponse);
                    callbacks.issueAlert("OpenID Login on: "+iri.getUrl().toString());
                    return true;
                }
                p = Pattern.compile("X-XRDS-Location:\\s(https?:\\/\\/)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})", Pattern.CASE_INSENSITIVE);
                m = p.matcher(response);
                if (m.find()) {
                    markRequestResponse(httpRequestResponse, "OpenID Metadata", "green");
                    IRequestInfo iri = helpers.analyzeRequest(httpRequestResponse);
                    callbacks.issueAlert("OpenID Login on: "+iri.getUrl().toString()); 
                    return true;
                }
                p = Pattern.compile("xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\"", Pattern.CASE_INSENSITIVE);
                m = p.matcher(response);
                if (m.find()) {
                    markRequestResponse(httpRequestResponse, "OpenID Metadata", "green");
                    IRequestInfo iri = helpers.analyzeRequest(httpRequestResponse);
                    callbacks.issueAlert("OpenID Login on: "+iri.getUrl().toString()); 
                    return true;
                }
            }
            return false;
	}
        
	private SSOProtocol checkRequestForBrowserId(IRequestInfo requestInfo, IHttpRequestResponse httpRequestResponse) {
            final List<IParameter> parameterList = requestInfo.getParameters();
            String host = requestInfo.getUrl().getHost();
            if(host.contains("persona.org")){
                if (parameterListContainsParameterName(parameterList, IN_REQUEST_BROWSERID_PARAMETER)) {
                    markRequestResponse(httpRequestResponse, "BrowserID", HIGHLIGHT_COLOR);
                    return new BrowserID(httpRequestResponse, "BrowserID", callbacks);
                }
            }
            return null;
	}

        private void markRequestResponse(IHttpRequestResponse httpRequestResponse, String message, String colour) {
            if(UIOptions.isHighlighted()){
                httpRequestResponse.setHighlight(colour);
            }
            final String oldComment = httpRequestResponse.getComment();
            if (oldComment != null && !oldComment.isEmpty()) {
                    httpRequestResponse.setComment(String.format("%s, %s", oldComment, message));
            } else {
                    httpRequestResponse.setComment(message);
            }
            Logging.getInstance().log(getClass(), message, Logging.DEBUG);
	}
}
