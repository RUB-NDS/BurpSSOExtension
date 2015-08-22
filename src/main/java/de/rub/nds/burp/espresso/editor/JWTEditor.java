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
import burp.IResponseInfo;
import burp.ITextEditor;
import de.rub.nds.burp.espresso.gui.UISourceViewer;
import de.rub.nds.burp.utilities.Encoding;
import java.awt.Component;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTabbedPane;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.json.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * TODO:
 * Create a new Template Class for the SSO protocol editors.
 * This is not used yet!
 */ 

/**
 * Abstract class for Editors.
 * @author Tim Guenther
 * @version 0.0
 */
public class JWTEditor implements IMessageEditorTabFactory{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public JWTEditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new InputTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //
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

        //
        // implement IMessageEditorTab
        //
        @Override
        public String getTabCaption() {
                return parameterName;
        }

        @Override
        public Component getUiComponent() {
                return editor;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
                return isJWT(content, isRequest);
        }

        private boolean isJWT(byte[] content, boolean isRequest) {
            return getJWT(content, isRequest) != null;
        }

        private String getJWT(byte[] content, boolean isRequest){
            if(content != null){
                IParameter jwt = helpers.getRequestParameter(content, "assertion");
                if(jwt == null){
                    if(isRequest){
                            IRequestInfo iri = helpers.analyzeRequest(content);
                            if(iri.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                                String body = (new String(content)).substring(iri.getBodyOffset());
                                try {
                                    JSONObject json = (JSONObject)new JSONParser().parse(body);
                                    body = json.getString("assertion");
                                } catch (Exception e) {
                                    new PrintWriter(callbacks.getStderr(),true).println("JWTEditor.getJWT: "+e.toString());
                                    return "";
                                }
                                return body;
                            }
                        }
                } else {
                    return jwt.getValue();
                }
            }
            return null;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                
                String jwt = getJWT(content, isRequest);
                if(jwt != null){
                    // deserialize the parameter value
                    String[] jwt_list = decode(jwt);

                    txtInput.setText(jwt.getBytes());
                    txtInput.setText(helpers.stringToBytes(jwt));
                    txtInput.setEditable(editable);
                    try{
                        sourceViewerHeader.setText(new JSONObject(jwt_list[0]).toString(1), SyntaxConstants.SYNTAX_STYLE_JSON);
                        sourceViewerPayload.setText(new JSONObject(jwt_list[1]).toString(1), SyntaxConstants.SYNTAX_STYLE_JSON);
                        sourceViewerSignature.setText(jwt_list[2], SyntaxConstants.SYNTAX_STYLE_NONE);
                    } catch(Exception e){
                        new PrintWriter(callbacks.getStderr(),true).println("JWTEditor.setMessage: "+e.toString());
                    }
                }
            }

            // remember the displayed content
            currentMessage = content;
        }

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

        @Override
        public boolean isModified() {
                return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
                return txtInput.getSelectedText();
        }

        public String[] decode(String input){
            try{
                if(Encoding.isURLEncoded(input)){
                    input = helpers.urlDecode(input);
                }
                if(Encoding.isBase64Encoded(input)){
                    input = helpers.bytesToString(helpers.base64Decode(input));
                }
                String[] jwt_list = input.split("\\.");
                String[] tmp = {"","",""};
                Decoder b64 = Base64.getDecoder();
                for(int i = 0; i<2; i++){
                    tmp[i] = helpers.bytesToString(b64.decode(jwt_list[i]));
                }
                tmp[2] = jwt_list[2];

                return tmp;
            } catch(Exception e){
                new PrintWriter(callbacks.getStderr(),true).println("JWTEditor.decode: "+e.toString());
            }
            return null;
        }

    }
    
}
