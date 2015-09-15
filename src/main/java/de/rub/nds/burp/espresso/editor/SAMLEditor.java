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
import burp.ITextEditor;
import de.rub.nds.burp.espresso.gui.UISourceViewer;
import de.rub.nds.burp.espresso.gui.attacker.UISAMLAttacker;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.XMLHelper;
import de.rub.nds.burp.utilities.listeners.AbstractCodeEvent;
import de.rub.nds.burp.utilities.listeners.ICodeListener;
import de.rub.nds.burp.utilities.listeners.SourceCode;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.IOException;
import java.util.zip.DataFormatException;
import javax.swing.JTabbedPane;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

/**
 *
 * @author Tim Guenther, Christian Mainka
 */
public class SAMLEditor implements IMessageEditorTabFactory{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private UISAMLAttacker uisa = null;
    
    private final String samlRequest = "SAMLRequest";
    private final String samlResponse = "SAMLResponse";

    public SAMLEditor(IBurpExtenderCallbacks callbacks) {
            this.callbacks = callbacks;
            this.helpers = callbacks.getHelpers();
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
            // create a new instance of our custom editor tab
            return new Base64InputTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //
    class Base64InputTab implements IMessageEditorTab, ICodeListener {

        private boolean editable;
        private ITextEditor txtInput;
        private JTabbedPane editor;
        private UISourceViewer sourceViewer;
        private boolean attackerModified = false;

        private byte[] currentMessage;

        private String samlType = "SAMLEditor";
        private IParameter saml = null;

        public Base64InputTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            editor = new JTabbedPane();

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
            
            // create a source code viewer
            sourceViewer = new UISourceViewer();
            editor.addTab("Source Code", sourceViewer);
            
        }

        //
        // implement IMessageEditorTab
        //
        @Override
        public String getTabCaption() {
            return "SAML";
        }

        @Override
        public Component getUiComponent() {
            return editor;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return isRequest && isSAML(content);
        }


        private boolean isSAML(byte[] content) {
            saml = helpers.getRequestParameter(content, samlRequest);
            if (null != saml){
                samlType = samlRequest;
                return true;
            }
            saml = helpers.getRequestParameter(content, samlResponse);
            if (null != saml){
                samlType = samlResponse;
                return true;
            }
            return false;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            editor.addTab(samlType, txtInput.getComponent());
            
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
                sourceViewer.setText(null, null);
                editor.setEnabled(false);
                if(uisa != null){
                    uisa.setEnabled(false);
                }
            } else if(saml != null){
                editor.setEnabled(true);

                if(samlType.equals(samlResponse)){
                    
                    // deserialize the parameter value
                    String xml = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(saml.getValue())));

                    //If editable is true, it is in the Burp Intercepter
                    if(editable && uisa == null){
                        uisa = new UISAMLAttacker(xml, txtInput);
                        editor.addTab("Attacker", uisa);
                        SourceCode.addCodeListener(this);
                    }
                    uisa.setEnabled(true);

                    //Pretty Print xml
                    String xmlpretty = XMLHelper.format(xml, 2);
                    txtInput.setText(xml.getBytes());
                    txtInput.setEditable(editable);
                    sourceViewer.setText(xmlpretty, SyntaxConstants.SYNTAX_STYLE_XML);
                }

                if(samlType.equals(samlRequest)){
                    try {
                        // deserialize the parameter value
                        String xml = decodeRedirectFormat(saml.getValue());

                        //If editable is true, it is in the Burp Intercepter
                        if(editable && uisa == null){
                            uisa = new UISAMLAttacker(xml, txtInput);
                            editor.addTab("Attacker", uisa);
                            SourceCode.addCodeListener(this);
                        }
                        uisa.setEnabled(true);
                        
                        //Pretty print XML
                        String xmlpretty = XMLHelper.format(xml, 2);
                        txtInput.setText(xml.getBytes());

                        sourceViewer.setText(xmlpretty, SyntaxConstants.SYNTAX_STYLE_XML);
                    } catch (IOException | DataFormatException e) {
                        txtInput.setText(saml.getValue().getBytes());
                    }
                    txtInput.setEditable(editable);
                }
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            
            if(samlType.equals(samlResponse)){
                // reserialize the data
                byte[] text = txtInput.getText();
                String input = helpers.urlEncode(helpers.base64Encode(text));

                // update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter(samlResponse, input, IParameter.PARAM_BODY));
            }

            if(samlType.equals(samlRequest)){
                // reserialize the data
                byte[] textBytes = txtInput.getText();
                String input;
                try {
                        input = encodeRedirectFormat(textBytes);
                } catch (IOException ex) {
                        input = new String(textBytes);
                }

                // update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter(samlRequest, input, IParameter.PARAM_URL));
            }
            return currentMessage;
        }

        @Override
        public boolean isModified() {
                return txtInput.isTextModified() || attackerModified;
        }

        @Override
        public byte[] getSelectedData() {
                return txtInput.getSelectedText();
        }
        
        public String encodeRedirectFormat(byte[] samlXML) throws IOException {
//          ByteArrayOutputStream os = new ByteArrayOutputStream();
//          DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(os);
//          deflaterOutputStream.write(samlXML);
//          deflaterOutputStream.close();
//          os.close();
            byte[] compressed = Compression.compress(samlXML);
            String base64encoded = helpers.base64Encode(compressed);
            return helpers.urlEncode(base64encoded);
        }

        public String decodeRedirectFormat(String input) throws IOException, DataFormatException {
            String urlDecoded = helpers.urlDecode(input);
            byte[] base64decoded = helpers.base64Decode(urlDecoded);
            byte[] decompressed = Compression.decompress(base64decoded);
            String result = new String(decompressed);
            return result;
        }

        @Override
        public void setCode(AbstractCodeEvent evt) {
            //Update views
            String samlRaw = evt.getCode();
            txtInput.setText(samlRaw.getBytes());
            String samlPretty = XMLHelper.format(samlRaw, 2);
            sourceViewer.setText(samlPretty, SyntaxConstants.SYNTAX_STYLE_XML);
            
            //Update current Message with new data
            currentMessage = getMessage();
            
            //Show data is modified
            attackerModified = true;
        }

        @Override
        protected void finalize( ) throws Throwable   {
            SourceCode.removeCodeListener(this);
            super.finalize();
        }
    }
}
