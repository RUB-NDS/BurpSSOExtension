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
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import de.rub.nds.burp.utilities.listeners.saml.SamlCodeEvent;
import java.awt.Component;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.zip.DataFormatException;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

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

    class InputTab implements IMessageEditorTab {

        private final boolean editable;
        private final JTabbedPane guiContainer;

        private final UISourceViewer sourceViewer;
        private final UIRawEditor rawEditor;
        private final UISAMLAttacker samlAttacker;
        
        private boolean rawEditorSelected = false;
        private boolean decDeflateActive;
        private boolean decURLActive;
        private boolean decBase64Active;
        
        private byte[] currentMessage;
        private byte[] unmodifiedMessage;
        private String encodedSAML;
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
            guiContainer.addTab("SAML", rawEditor.getComponent());
            
            // create the attacker
            samlAttacker = new UISAMLAttacker();
            samlAttacker.setListeners(listeners);
            guiContainer.addTab("Attacker", samlAttacker);
            
            guiContainer.addChangeListener(new ChangeListener() {
               @Override
                public void stateChanged(ChangeEvent ce) {
                    if(rawEditorSelected == true && rawEditor.isTextModified()) {
                        listeners.notifyAll(new SamlCodeEvent(rawEditor, new String(rawEditor.getText())));
                        Logging.getInstance().log(rawEditor.getClass(), "Notify all Listeners.", Logging.DEBUG);
                        rawEditorSelected = false;
                    }
                    rawEditorSelected = guiContainer.getSelectedIndex() == 1;
                }
            });
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
            if(isRequest && isSAML(content)){
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
                return true;
            }
            samlContent = helpers.getRequestParameter(content, samlResponse);
            if (null != samlContent){
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
                    rawEditor.disableModifyFeatures();
                    guiContainer.remove(2);
                } catch(IndexOutOfBoundsException e){
                    //Do nothing!
                } catch(Exception e){
                    Logging.getInstance().log(getClass(), e);
                }
            }
            // save message
            currentMessage = content;
            unmodifiedMessage = content;
            // remember the displayed content
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
                rawEditor.getChangeHttpMethodCheckBox().setEnabled(true);
                samlAttacker.setEnabled(true);
                guiContainer.setEnabled(true);
                
                // change the name of the rawEditor to the Parametername
                guiContainer.setTitleAt(1, samlContent.getName());   
                
                // disable checkbox to change HTTP-method
                // only enable if message is GET oder POST
                if(!helpers.analyzeRequest(content).getMethod().equalsIgnoreCase("GET") 
                        && !helpers.analyzeRequest(content).getMethod().equalsIgnoreCase("POST")) {
                    rawEditor.getChangeHttpMethodCheckBox().setEnabled(false);
                }                   
                Logging.getInstance().log(getClass(), "Begin XML deserialization.", Logging.DEBUG);

                // deserialize the parameter value
                String xml = null;
                try {
                    xml = decodeSamlParam(samlContent.getValue(), samlContent.getType());
                } catch (IOException | DataFormatException e) {
                    xml = samlContent.getValue();
                    Logging.getInstance().log(getClass(), "Failed to decode" + samlContent.getName() , Logging.ERROR);
                }
                Logging.getInstance().log(getClass(), samlContent.getName() + "deserialized.", Logging.DEBUG);

                //Notify all tabs with the new saml code.
                if(xml != null){
                    encodedSAML = xml;
                    listeners.notifyAll(new SamlCodeEvent(this, xml));
                    Logging.getInstance().log(getClass(), "Notify all tabs.", Logging.DEBUG);
                }
            } else {
                Logging.getInstance().log(getClass(), "content != null, samlContent == null", Logging.ERROR);
            }
            Logging.getInstance().log(getClass(), "End setMessage().", Logging.DEBUG);
        }
        
        /**
         * 
         * @return Get the current message.
         */
        @Override
        public byte[] getMessage() {
            if(!isModified()) {
                return unmodifiedMessage;
            }
            String input;
            // reserialize the data
            try {
                input = encodeSamlParam(rawEditor.getText());
            } catch (IOException ex) {
                input = new String(samlContent.getValue().getBytes());
                Logging.getInstance().log(getClass(), "failed to re-encode SAML param", Logging.ERROR);
            }          
            // update the message
            // only update the saml parameter with new value
            if (!rawEditor.getChangeHttpMethodCheckBox().isSelected()) {   
                currentMessage = helpers.updateParameter(currentMessage, helpers.buildParameter(samlContent.getName(), input, samlContent.getType()));
            // update the saml parameter with new value and switch all parameters from url to body or body from url
            } else if (rawEditor.getChangeAllParameters().isSelected()) {
                currentMessage = helpers.updateParameter(currentMessage, helpers.buildParameter(samlContent.getName(), input, samlContent.getType()));
                currentMessage = helpers.toggleRequestMethod(currentMessage);
            // update the saml parameter with new value and switch only saml parameter from url to body or body to url
            } else {
                List<IParameter> parameters = helpers.analyzeRequest(currentMessage).getParameters();
                for (IParameter param : parameters) {
                    currentMessage = helpers.removeParameter(currentMessage, param);
		}
                currentMessage = helpers.toggleRequestMethod(currentMessage);
                for (IParameter param : parameters) {
                    if (samlContent.getValue().equals(param.getValue())
                            && samlContent.getName().equals(param.getName())
                            && samlContent.getType() == param.getType()) {
                        switch (samlContent.getType()) {
                        case IParameter.PARAM_URL:
                            currentMessage = helpers.addParameter(currentMessage, helpers.buildParameter(samlContent.getName(), input, IParameter.PARAM_BODY));
                            break;
                        case IParameter.PARAM_BODY:
                            currentMessage = helpers.addParameter(currentMessage, helpers.buildParameter(samlContent.getName(), input, IParameter.PARAM_URL));
                            break;                        
                        }
                    } else {
                        currentMessage = helpers.addParameter(currentMessage,param);
                    }
                }  
            }
            return currentMessage;
        }
        
        /**
         * Indicator for the proxy to show the original and edited tab.
         * @return True if message is modified by the user.
         */
        @Override
        public boolean isModified() {
            return encodedSAML.compareTo(new String(rawEditor.getText())) != 0
                    || rawEditor.getChangeHttpMethodCheckBox().isSelected()
                    || rawEditor.getChangeAllParameters().isSelected() 
                    || decBase64Active != rawEditor.getBase64CheckBox().isSelected()
                    || decURLActive != rawEditor.getUrlCheckBox().isSelected()
                    || decDeflateActive != rawEditor.getDeflateCheckBox().isSelected();
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
         * @return Encoded SAML message.
         */
        public String encodeSamlParam(byte[] input) throws IOException {
            if (rawEditor.getDeflateCheckBox().isSelected()) {
                input = Compression.compress(input);
            }
            if (rawEditor.getBase64CheckBox().isSelected()) {
                input = helpers.base64Encode(input).getBytes();
            }
            if (rawEditor.getUrlCheckBox().isSelected()) {
                input = helpers.urlEncode(input);
            }
            return new String(input);    
        }

        /**
         * 
         * @param samlParam The encoded SAML parameter.
         * @param parameterType If set to IParameter.PARAM_URL, Deflate (de-)compression is used
         * @return Decoded SAML message as XML string.
         * @throws IOException {@link java.io.IOException}
         * @throws DataFormatException {@link java.util.zip.DataFormatException}
         */
        public String decodeSamlParam(String samlParam, byte parameterType) throws IOException, DataFormatException {
            byte [] tmp;
            decDeflateActive = false;
            decURLActive = false;
            decBase64Active = false;
            rawEditor.clearCheckBoxes();
            if(Encoding.isURLEncoded(samlParam)) {
                samlParam = helpers.urlDecode(samlParam);
                rawEditor.getUrlCheckBox().setSelected(true);        
                decURLActive = true;
            }
            if(Encoding.isBase64Encoded(samlParam)) {
                tmp = helpers.base64Decode(samlParam);
                rawEditor.getBase64CheckBox().setSelected(true);
                decBase64Active = true;
            } else {
                tmp = samlParam.getBytes();
            }
            if (Encoding.isDeflated(tmp)) {
                rawEditor.getDeflateCheckBox().setSelected(true);
                decDeflateActive = true;
                tmp = Compression.decompress(tmp);
            }
            return new String(tmp);
        }
    }
}
