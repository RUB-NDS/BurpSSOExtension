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
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITextEditor;
import de.rub.nds.burp.espresso.editor.saml.UISourceViewer;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import java.awt.Component;
import javax.swing.JTabbedPane;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.json.JSONObject;

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
public class JSONEditor implements IMessageEditorTabFactory{

    private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	public JSONEditor(IBurpExtenderCallbacks callbacks) {
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
		private ITextEditor burpEditor;
                private JTabbedPane guiContainer;
                private UISourceViewer sourceViewer;
                
		private byte[] currentMessage;

		final String tabName = "JSON";
		public InputTab(IMessageEditorController controller, boolean editable) {
			this.editable = editable;
                        
                        guiContainer = new JTabbedPane();
                        
			// create an instance of Burp's text editor, to display our deserialized data
			burpEditor = callbacks.createTextEditor();
			burpEditor.setEditable(editable);
                        
                        // create a source code viewer
                        sourceViewer = new UISourceViewer();
                        guiContainer.addTab("JSON Viewer", sourceViewer);
                        guiContainer.addTab("Raw", burpEditor.getComponent());
		}

		//
		// implement IMessageEditorTab
		//
		@Override
		public String getTabCaption() {
			return tabName;
		}

		@Override
		public Component getUiComponent() {
			return guiContainer;
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
                        if(isJSON(content)){
                            Logging.getInstance().log(getClass(), "Editor@"+System.identityHashCode(this)+" attached.", Logging.DEBUG);
                            return true;
                        }
			return false;
		}

		private boolean isJSON(byte[] content) {
			IRequestInfo iri = helpers.analyzeRequest(content);
                        return iri.getContentType() == IRequestInfo.CONTENT_TYPE_JSON;
		}
                
                private String getJSON(byte[] content, boolean isRequest){
                    if(isRequest){
                        IRequestInfo iri = helpers.analyzeRequest(content);
			String body = (new String(content)).substring(iri.getBodyOffset());
                        return body;
                        
                    } else {
                        IResponseInfo iri = helpers.analyzeResponse(content);
                        String body = (new String(content)).substring(iri.getBodyOffset());
                        return body;
                    }
                }

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			if (content == null) {
                            // clear our display
                            burpEditor.setText(null);
                            burpEditor.setEditable(false);
                            sourceViewer.setText(null, null);
                            guiContainer.setEnabled(false);
			} else {
                            guiContainer.setEnabled(true);
                            
                            String input = getJSON(content, isRequest);

                            // deserialize the parameter value
                            String json = decode(input);
                            burpEditor.setText(json.getBytes());
                            sourceViewer.setText(new JSONObject(json).toString(2), SyntaxConstants.SYNTAX_STYLE_JSON);
                            burpEditor.setText(helpers.stringToBytes(input));

                            burpEditor.setEditable(editable);
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
			return burpEditor.isTextModified();
		}

		@Override
		public byte[] getSelectedData() {
			return burpEditor.getSelectedText();
		}

		public String decode(String input){
                    if(Encoding.isURLEncoded(input)){
                        input = helpers.urlDecode(input);
                    }
                    if(Encoding.isBase64Encoded(input)){
                        input = helpers.bytesToString(helpers.base64Decode(input));
                    }
                    if(Encoding.isJSON(input)){
                        return input;
                    }
                    return null;
		}

	}
    
}
