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
package de.rub.nds.burp.espresso.intruder.xsw;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IParameter;
import de.rub.nds.burp.espresso.gui.attacker.saml.UIPreview;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import javax.swing.JOptionPane;
import javax.xml.xpath.XPathExpressionException;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * XSW Payload Generator.
 *
 * @author Nurullah Erinola
 */
public class XSWPayloadFactory implements IIntruderPayloadGeneratorFactory {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    public XSWPayloadFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public String getGeneratorName() {
        return "XSW Payloads";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new XSWPayloadFactory.XSWPayloadGenerator(attack);
    }
    
    class XSWPayloadGenerator implements IIntruderPayloadGenerator {
                
        private XSWInputJDialog dialog;
        private IIntruderAttack attack;
        private int payloadIndex = 0;
        private String xmlMessage;
        private Document xmlDoc;
        private ArrayList<byte[]> payloads;
        
        public XSWPayloadGenerator(IIntruderAttack attack) {
            this.attack = attack;
            payloads = new ArrayList<>();
            // Try to get payload
            String template = helpers.bytesToString(attack.getRequestTemplate());
            if(StringUtils.countMatches(template,"§") != 2) {
                JOptionPane.showMessageDialog(null, 
                    "More than one payload is selected! Select only one.\n Attack vectors cannot be generated.", 
                    "Error",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            xmlMessage = template.substring(template.indexOf("§")+1, template.lastIndexOf("§"));
            // Try to decode payload if possible
            try {
                xmlMessage = decode(xmlMessage);
            } catch (IOException | DataFormatException ex) {
                Logging.getInstance().log(getClass(), "Failed to decode payload", Logging.ERROR);
            }
            // Try to transform payload to document to check if is valid xml and generate attack vectors
            try {
                xmlDoc = DomUtilities.stringToDom(xmlMessage);
                dialog = new XSWInputJDialog(xmlMessage);
                generatePayloads();
            } catch (SAXException ex) {
                Logging.getInstance().log(getClass(), "Failed to transform payload to document", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                        "Selected message is not valid xml!\n Attack vectors cannot be generated.", 
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
        } 

        @Override
        public boolean hasMorePayloads() {
            return payloadIndex < payloads.size();
        }

        @Override
        public byte[] getNextPayload(byte[] bytes) {
            byte[] payload = payloads.get(payloadIndex);
            payloadIndex++;
            return payload;
        }

        @Override
        public void reset() {
            payloadIndex = 0;
        }
        
        private void generatePayloads() {
            // Init manager
            SignatureManager signatureManager = new SignatureManager();
            signatureManager.setDocument(xmlDoc);
            List<Payload> payloadList = signatureManager.getPayloads();
            // Checks if signature exits to attack
            if (payloadList.isEmpty()) {
                Logging.getInstance().log(getClass(), "No Payload found", Logging.INFO);
                return;
            }
            for (int i = 0; i < payloadList.size(); i++) {
                payloadList.get(i).setValue(payloadList.get(i).getValue());
            }
            // Init oracle
            Document samlDoc = signatureManager.getDocument();
            SchemaAnalyzer samlSchemaAnalyser = SchemaAnalyzerFactory.getInstance(SchemaAnalyzerFactory.SAML);
            WrappingOracle wrappingOracle = new WrappingOracle(samlDoc, payloadList, samlSchemaAnalyser);
            // Save attack vectors
            for (int i = 0; i < wrappingOracle.maxPossibilities(); i++) {
                try {
                    // Get vector
                    Document attackDoc = wrappingOracle.getPossibility(i);
                    // Replace values
                    for (Map.Entry pair : dialog.getValuePairs().entrySet()) {
                        Node node = DomUtilities.evaluateXPath(attackDoc, pair.getKey().toString()).get(0);
                        node.setTextContent(pair.getValue().toString());
                    }               
                    // Encode vector
                    String attackString = DomUtilities.domToString(attackDoc);
                    payloads.add(encode(attackString).getBytes());
                } catch (XPathExpressionException | InvalidWeaknessException ex) {
                    Logging.getInstance().log(getClass(), "Failed to generate XSW vector: " + i, Logging.ERROR);
                }
            }
        }
        
        private String decode(String samlParam) throws IOException, DataFormatException {
            byte [] tmp;
            if(Encoding.isURLEncoded(samlParam)) {
                samlParam = helpers.urlDecode(samlParam);
            }
            if(Encoding.isBase64Encoded(samlParam)) {
                tmp = helpers.base64Decode(samlParam);
            } else {
                tmp = samlParam.getBytes();
            }
            if (Encoding.isDeflated(tmp)) {
                tmp = Compression.decompress(tmp);
            }
            return new String(tmp);
        }
              
        private String encode(String vector) {
            byte[] tmp = vector.getBytes();
            if (dialog.getEnflateChoice()) {
                try {
                    tmp = Compression.compress(tmp);
                } catch (IOException ex) {
                    Logging.getInstance().log(getClass(), "Failed to compress parameter", Logging.ERROR);
                }
            }
            if (dialog.getBase64Choice()) {
                tmp = helpers.base64Encode(tmp).getBytes();
            }
            if (dialog.getUrlChoice()) {
                tmp = helpers.urlEncode(tmp);
            }
            return new String(tmp);
        }
    }
}
