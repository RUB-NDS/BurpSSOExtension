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
package de.rub.nds.burp.espresso.editor;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import burp.ITextEditor;
import de.rub.nds.burp.espresso.editor.saml.UISourceViewer;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import java.awt.Component;
import java.util.Base64;
import java.util.Base64.Decoder;
import javax.swing.JTabbedPane;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * JSON Web Token (JWT) Editor.
 * Display decoded JWT syntax highlighted.
 * @author Tim Guenther
 * @version 1.0
 */ 

/**
 * Abstract class for Editors.
 * @author Tim Guenther
 * @version 0.0
 */
public class JWTEditor implements IMessageEditorTabFactory{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /**
     * JWT Editor.
     * Create a new JWTEditor factory.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     */
    public JWTEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Create a new Instance of Burps own Request/Response Viewer (IMessageEditorTab).
     * @param controller {@link burp.IMessageEditorController}
     * @param editable True if message is editable, false otherwise.
     * @return {@link burp.IMessageEditorTab}
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new InputTab(controller, editable);
    }

    /**
     * Implementing the IMessageEditorTab.
     * Class with the UI components and the businesses logic.
     */
    class InputTab implements IMessageEditorTab {

        private boolean editable;
        private ITextEditor txtInput;
        private JTabbedPane editor;
        private UISourceViewer sourceViewerHeader;
        private UISourceViewer sourceViewerPayload;
        private UISourceViewer sourceViewerSignature;

        private byte[] currentMessage;

        final String parameterName = "JWT";
        public InputTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            editor = new JTabbedPane();
            
            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);

            // create a source code viewer
            sourceViewerHeader = new UISourceViewer();
            sourceViewerPayload = new UISourceViewer();
            sourceViewerSignature = new UISourceViewer();
            editor.addTab("Header", sourceViewerHeader);
            editor.addTab("Payload", sourceViewerPayload);
            editor.addTab("Base64(Signature)", sourceViewerSignature);
            editor.addTab("Raw", txtInput.getComponent());
        }

        /**
         * 
         * @return Name of the new tab.
         */
        @Override
        public String getTabCaption() {
                return parameterName;
        }

        /**
         * 
         * @return The UI component to attach.
         */
        @Override
        public Component getUiComponent() {
                return editor;
        }

        /**
         * 
         * @param content The http message as bytes. 
         * @param isRequest True if request, false if response.
         * @return True if the tab should be attached, false otherwise.
         */
        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
                if(isJWT(content, isRequest)){
                    Logging.getInstance().log(getClass(), "Editor@"+System.identityHashCode(this)+" attached.", Logging.DEBUG);
                    return true;
                }
                return false;
        }
        
        /**
         * 
         * @param content The http message as bytes. 
         * @return True if JWT is found in the message.
         */        /**
                 * 
                 * @param content The http message as bytes. 
                 * @return True if JSON is found in the message.
                 */
        private boolean isJWT(byte[] content, boolean isRequest) {
            return getJWT(content, isRequest) != null;
        }
        
        /**
         * Get the body of the http message.
         * @param content The http message as bytes. 
         * @param isRequest True if request, false if response.
         * @return JSON as a string.
         */
        private String getJWT(byte[] content, boolean isRequest){
            if(content != null){
                IParameter jwt = helpers.getRequestParameter(content, "assertion");
                jwt = helpers.getRequestParameter(content, "id_token");
                jwt = helpers.getRequestParameter(content, "access_token");
                if(jwt == null){
                    if(isRequest){
                            IRequestInfo iri = helpers.analyzeRequest(content);
                            if(iri.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                                String body = (new String(content)).substring(iri.getBodyOffset());
                                String tmp_body = null;
                                try {
                                    JSONObject json = (JSONObject)new JSONParser().parse(body);
                                    tmp_body = (String) json.get("assertion");
                                } catch (ClassCastException e){
                                    return null;
                                } catch (Exception e) {
                                    Logging.getInstance().log(getClass(), e);
                                }
                                return tmp_body;
                            }
                        }
                } else {
                    return jwt.getValue();
                }
            }
            return null;
        }
        /**
         * Set the message to display in the tab.
         * @param content The http message as bytes.
         * @param isRequest True if request, false if response.
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
                sourceViewerHeader.setText(null, null);
                sourceViewerPayload.setText(null, null);
                sourceViewerSignature.setText(null, null);
                editor.setEnabled(false);
            } else {
                editor.setEnabled(true);
                
                String jwt = getJWT(content, isRequest);
                if(jwt != null){
                    // deserialize the parameter value
                    String[] jwt_list = decode(jwt);
                    if(jwt_list.length > 0){
                        txtInput.setText(jwt.getBytes());
                        txtInput.setText(helpers.stringToBytes(jwt));
                        txtInput.setEditable(editable);
                        try{
                            sourceViewerHeader.setText(new org.json.JSONObject(jwt_list[0]).toString(2), SyntaxConstants.SYNTAX_STYLE_JSON);
                            sourceViewerPayload.setText(new org.json.JSONObject(jwt_list[1]).toString(2), SyntaxConstants.SYNTAX_STYLE_JSON);
                            sourceViewerSignature.setText(jwt_list[2], SyntaxConstants.SYNTAX_STYLE_NONE);
                        } catch(Exception e){
                            Logging.getInstance().log(getClass(), e);
                        }
                    }
                }
            }

            // remember the displayed content
            currentMessage = content;
        }
        
        /**
         * 
         * @return Get the current message.
         */
        @Override
        public byte[] getMessage() {
                // determine whether the user modified the deserialized data
//			if (txtInput.isTextModified()) {
//				// reserialize the data
//				byte[] textBytes = txtInput.getText();
//				String input;
//				try {
//					input = encodeRedirectFormat(textBytes);
//				} catch (IOException ex) {
//					input = new String(textBytes);
//				}
//
//				// update the request with the new parameter value
//				return helpers.updateParameter(currentMessage, helpers.buildParameter(parameterName, input, IParameter.PARAM_URL));
//			} else {
                        return currentMessage;
//			}
        }
        
        /**
         * Indicator for the proxy to show the original and edited tab.
         * @return True if message is modified by the user.
         */
        @Override
        public boolean isModified() {
                return txtInput.isTextModified();
        }

        /**
         * 
         * @return Data selected by the user.
         */
        @Override
        public byte[] getSelectedData() {
                return txtInput.getSelectedText();
        }

        /**
         * Decode the JWT String.
         * @param input The data to decode.
         * @return The decoded String.
         */
        public String[] decode(String input){
            try{
                if(Encoding.isURLEncoded(input)){
                    input = helpers.urlDecode(input);
                }
                if(Encoding.isBase64Encoded(input)){
                    input = helpers.bytesToString(helpers.base64Decode(input));
                }
                String[] jwt_list = input.split("\\.");
                if(jwt_list.length > 0){
                    String[] tmp = {"","",""};
                    Decoder b64 = Base64.getDecoder();
                    for(int i = 0; i<2; i++){
                        tmp[i] = helpers.bytesToString(b64.decode(jwt_list[i]));
                    }
                    tmp[2] = jwt_list[2];
                    return tmp;
                }
            } catch(Exception e){
                Logging.getInstance().log(getClass(), e);
            }
            return null;
        }

    }
    
}
