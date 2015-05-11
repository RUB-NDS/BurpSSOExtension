/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.threecurity.burp.sso;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HttpMarker implements IHttpListener {

	private String[] OPENID_TOKEN_PARAMETER = {"openid.return_to"};

	private static final Set<String> IN_REQUEST_OPENID2_TOKEN_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[] {"openid.claimed_id", "openid.op_endpoint"}
	));

	private static final Set<String> IN_REQUEST_OAUTH_TOKEN_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[] {"redirect_uri", "scope", "client_id"}
	));

	private static final Set<String> IN_REQUEST_SAML_TOKEN_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[] {"SAMLResponse"}
	));

	private static final Set<String> IN_REQUEST_SAML_REQUEST_PARAMETER = new HashSet<String>(Arrays.asList(
		new String[] {"SAMLRequest"}
	));

	private static final String HIGHLIGHT_COLOR = "yellow";

	private IBurpExtenderCallbacks callbacks;

	private IExtensionHelpers helpers;

	public HttpMarker(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public void processHttpMessage(int flag, boolean isRequest, IHttpRequestResponse httpRequestResponse) {
		// only flag messages sent/received by the proxy
		if (flag == IBurpExtenderCallbacks.TOOL_PROXY) {
			if (isRequest) {
				processHttpRequest(flag, httpRequestResponse);
			} else {
				processHttpResponse(flag, httpRequestResponse);
			}
		}
	}

	private void processHttpResponse(int flag, IHttpRequestResponse httpRequestResponse) {
//			httpResponse.setComment("Flagged by me with " + flag);
		final byte[] responseBytes = httpRequestResponse.getResponse();
		IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
	}

	private void processHttpRequest(int flag, IHttpRequestResponse httpRequestResponse) {
		IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
		final List<IParameter> parameters = requestInfo.getParameters();
		for (IParameter p : parameters) {
			final String parameterName = p.getName();
			if (IN_REQUEST_OPENID2_TOKEN_PARAMETER.contains(parameterName)) {
				httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);
				httpRequestResponse.setComment("OpenID v2 Token");
				break;
			}

			if (IN_REQUEST_OAUTH_TOKEN_PARAMETER.contains(parameterName)) {
				httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);
				httpRequestResponse.setComment("OAuth Token");
				break;
			}

			if (IN_REQUEST_SAML_REQUEST_PARAMETER.contains(parameterName)) {
				httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);
				httpRequestResponse.setComment("SAML Authenticaiton Request");
				break;
			}

			if (IN_REQUEST_SAML_TOKEN_PARAMETER.contains(parameterName)) {
				httpRequestResponse.setHighlight(HIGHLIGHT_COLOR);
				httpRequestResponse.setComment("SAML Token");
				break;
			}
		}
	}
}
