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
package de.rub.nds.burp.espresso.editor.saml;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import de.rub.nds.burp.espresso.gui.attacker.saml.UISAMLAttacker;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.listeners.AbstractCodeEvent;
import de.rub.nds.burp.utilities.listeners.ICodeListener;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import de.rub.nds.burp.utilities.listeners.saml.SamlCodeEvent;
import java.awt.Component;
import java.io.IOException;
import java.util.zip.DataFormatException;
import javax.swing.JTabbedPane;

/**
 * SAML Editor.
 * Display decoded SAML syntax highlighted.
 * @author Tim Guenther
 * @version 1.0
 */
public class SAMLEditor implements IMessageEditorTabFactory{
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    
    private final String samlRequest = "SAMLRequest";
    private final String samlResponse = "SAMLResponse";
    
    /**
     * SAML Editor.
     * Create a new SAMLEditor factory.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     * 
     */
    public SAMLEditor(IBurpExtenderCallbacks callbacks) {
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

    class InputTab implements IMessageEditorTab, ICodeListener {

        private final boolean editable;
        private final JTabbedPane guiContainer;

        private final UISourceViewer sourceViewer;
        private final UIRawEditor rawEditor;
        private final UISAMLAttacker samlAttacker;
        
        private boolean attackerModified = false;

        private byte[] currentMessage;
        private String samlParamtername = "SAML???"; // A placeholder at the beginning.
        private IParameter samlContent = null;
        
        private CodeListenerController listeners = new CodeListenerController();

        /**
         * Implementing the IMessageEditorTab.
         * Class with the UI components and the businesses logic.
         */
        public InputTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            guiContainer = new JTabbedPane();
            
            // create a source code viewer
            sourceViewer = new UISourceViewer();
            sourceViewer.setListener(listeners);
            guiContainer.addTab("Source Code", sourceViewer);
            
            // create a raw tab, its an instance of Burp's text editor, to display our deserialized data
            rawEditor = new UIRawEditor(callbacks, editable);
            rawEditor.setListener(listeners);
            guiContainer.addTab(samlParamtername, rawEditor.getComponent());
            
            // create the attacker
            samlAttacker = new UISAMLAttacker();
            samlAttacker.setListeners(listeners);
            guiContainer.addTab("Attacker", samlAttacker);
        }

        /**
         * 
         * @return Name of the new tab.
         */
        @Override
        public String getTabCaption() {
            return "SAML";
        }

        /**
         * 
         * @return The UI component to attach.
         */
        @Override
        public Component getUiComponent() {
            return guiContainer;
        }
        
        /**
         * 
         * @param content The http message as bytes. 
         * @param isRequest True if request, false if response.
         * @return True if the tab should be attached, false otherwise.
         */
        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            if(isSAML(content) && isRequest){
                Logging.getInstance().log(getClass(), "Editor@"+System.identityHashCode(this)+" attached.", Logging.DEBUG);
                return true;
            }
            return false;
        }

        /**
         * 
         * @param content The http message as bytes. 
         * @return True if SAML is found in the message.
         */
        private boolean isSAML(byte[] content) {
            samlContent = helpers.getRequestParameter(content, samlRequest);
            if (null != samlContent){
                samlParamtername = samlRequest;
                return true;
            }
            samlContent = helpers.getRequestParameter(content, samlResponse);
            if (null != samlContent){
                samlParamtername = samlResponse;
                return true;
            }
            return false;
        }
        
        /**
         * Set the message to display in the tab.
         * @param content The http message as bytes.
         * @param isRequest True if request, false if response.
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            Logging.getInstance().log(getClass(), "Start setMessage().", Logging.DEBUG);
            // Editor is not in the intercept tab.
            if(!editable){
                //remove the attacker
                try{
                    guiContainer.remove(2);
                } catch(IndexOutOfBoundsException e){
                    //Do nothing!
                } catch(Exception e){
                    Logging.getInstance().log(getClass(), e);
                }
            }
            
            if (content == null) {
                Logging.getInstance().log(getClass(), "Clear tabs.", Logging.DEBUG);
                // clear our tabs
                sourceViewer.setEnabled(false);
                rawEditor.setEnabled(false);
                samlAttacker.setEnabled(false);
                guiContainer.setEnabled(false);
            } else if(samlContent != null){
                // reactivate our tabs
                Logging.getInstance().log(getClass(), "Activate tabs.", Logging.DEBUG);
                sourceViewer.setEnabled(true);
                rawEditor.setEnabled(true);
                samlAttacker.setEnabled(true);
                guiContainer.setEnabled(true);
                
                //Change the name of the rawEditor to the Parametername
                guiContainer.setTitleAt(1, samlParamtername);
                
                Logging.getInstance().log(getClass(), "Begin XML deserialization.", Logging.DEBUG);
                String xml = null;

                switch (samlParamtername) {
                    case samlResponse:
                        // deserialize the parameter value
                        xml = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(samlContent.getValue())));
                        Logging.getInstance().log(getClass(), "SAMLResponse deserialized.", Logging.DEBUG);
                        break;
                    case samlRequest:
                        try {
                            // deserialize the parameter value
                            xml = decodeRedirectFormat(samlContent.getValue());
                            
                        } catch (IOException | DataFormatException e) {
                            xml = samlContent.getValue();
                        }   
                        Logging.getInstance().log(getClass(), "SAMLRequest deserialized.", Logging.DEBUG);
                        break;
                }
                
                //Notify all tabs with the new saml code.
                if(xml != null){
                    listeners.notifyAll(new SamlCodeEvent(this, xml));
                    Logging.getInstance().log(getClass(), "Notify all tabs.", Logging.DEBUG);
                }
            } else {
                Logging.getInstance().log(getClass(), samlContent.getValue(), Logging.DEBUG);
            }
            
            // remember the displayed content
            currentMessage = content;
            Logging.getInstance().log(getClass(), "End setMessage().", Logging.DEBUG);
        }
        
        /**
         * 
         * @return Get the current message.
         */
        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            String input;
            byte[] text = rawEditor.getText();
            
            // reserialize the data
            switch (samlParamtername) {
                case samlResponse:
                    input = helpers.urlEncode(helpers.base64Encode(text));
                    
                    // update the request with the new parameter value
                    return helpers.updateParameter(currentMessage, helpers.buildParameter(samlResponse, input, IParameter.PARAM_BODY));
                case samlRequest:
                    try {
                        input = encodeRedirectFormat(text);
                    } catch (IOException ex) {
                        input = new String(text);
                    }
                    
                    // update the request with the new parameter value
                    return helpers.updateParameter(currentMessage, helpers.buildParameter(samlRequest, input, IParameter.PARAM_URL));
            }
            return currentMessage;
        }
        
        /**
         * Indicator for the proxy to show the original and edited tab.
         * @return True if message is modified by the user.
         */
        @Override
        public boolean isModified() {
                return rawEditor.isTextModified() || attackerModified;
        }
        
        /**
         * 
         * @return Data selected by the user.
         */
        @Override
        public byte[] getSelectedData() {
                return rawEditor.getSelectedText();
        }
        
        /**
         * 
         * @param input The plain string.
         * @return Redirected format encoded string.
         * @throws IOException {@link java.io.IOException}
         */
        public String encodeRedirectFormat(byte[] input) throws IOException {
            byte[] compressed = Compression.compress(input);
            String base64encoded = helpers.base64Encode(compressed);
            return helpers.urlEncode(base64encoded);
        }

        /**
         * 
         * @param input The redirect encoded string.
         * @return Redirect format decode string.
         * @throws IOException {@link java.io.IOException}
         * @throws DataFormatException {@link java.util.zip.DataFormatException}
         */
        public String decodeRedirectFormat(String input) throws IOException, DataFormatException {
            String urlDecoded = helpers.urlDecode(input);
            byte[] base64decoded = helpers.base64Decode(urlDecoded);
            byte[] decompressed = Compression.decompress(base64decoded);
            String result = new String(decompressed);
            return result;
        }

        /**
         * Is called every time new Code is available.
         * @param evt {@link de.rub.nds.burp.utilities.listeners.AbstractCodeEvent} The new source code.
         */
        @Override
        public void setCode(AbstractCodeEvent evt) { 
            //Update current Message with new data
            currentMessage = getMessage();
            
            //Show data is modified by the attacker.
            if(!evt.getSource().equals(this)){
                attackerModified = true;
            }
            Logging.getInstance().log(getClass(), evt.getCode(), Logging.DEBUG);
        }

        /**
         * Set the listener for the editor.
         * @param listeners {@link de.rub.nds.burp.utilities.listeners.CodeListenerController}
         */
        @Override
        public void setListener(CodeListenerController listeners) {
            this.listeners = listeners;
        }
    }
}
