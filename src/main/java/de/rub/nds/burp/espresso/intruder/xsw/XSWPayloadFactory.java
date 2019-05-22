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
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.XMLHelper;
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
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
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
        private List<Payload> payloadList;
        
        public XSWPayloadGenerator(IIntruderAttack attack) {
            Logging.getInstance().log(getClass(), "Start signature wrapping.", Logging.INFO);
            this.attack = attack;
            payloads = new ArrayList<>();
            // Try to get payload
            String template = helpers.bytesToString(attack.getRequestTemplate());
            if(StringUtils.countMatches(template,"§") != 2) {
                Logging.getInstance().log(getClass(), "More than one payload is selected", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                    "More than one payload is selected! Select only one.\nAttack vectors cannot be generated.", 
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
            } catch (SAXException ex) {
                Logging.getInstance().log(getClass(), "Failed to transform payload to document", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                        "Selected message is not valid xml!\nAttack vectors cannot be generated.", 
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            getSignatures();
            generatePayloads();
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
        
        private void getSignatures() {
            SignatureManager signatureManager = new SignatureManager();
            signatureManager.setDocument(xmlDoc);
            payloadList = signatureManager.getPayloads();
        }
        
        private void generatePayloads() {
            // Checks if signature exits to attack
            if (payloadList.isEmpty()) {
                Logging.getInstance().log(getClass(), "No Payload found", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                        "No signature found for wrapping!\nAttack vectors cannot be generated.", 
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            } else if (payloadList.size() != 1) {
                Logging.getInstance().log(getClass(), "Multiple Payloads found.", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                        "Message contains multiple signature!\nAttacker works only for messages with one signature.", 
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            // Open new window
            dialog = new XSWInputJDialog(xmlMessage, payloadList);
            if (dialog.getValuePairs().size() <= 0) {
                Logging.getInstance().log(getClass(), "", Logging.ERROR);
                JOptionPane.showMessageDialog(null, 
                        "No values to replace entered!\nThe attacker need at least one value.", 
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            // Repalce values
            for (int i = 0; i < payloadList.size(); i++) {
                Document payload = XMLHelper.stringToDom(payloadList.get(i).getValue());
                for (Map.Entry pair : dialog.getValuePairs().entrySet()) {
                    try {
                        Node node = DomUtilities.evaluateXPath(payload, pair.getKey().toString()).get(0);
                        node.setTextContent(pair.getValue().toString());
                    } catch (XPathExpressionException ex) {
                        Logging.getInstance().log(getClass(), "Could not replace value.", Logging.ERROR);
                    }
                } 
                payloadList.get(i).setPayloadElement(payload.getDocumentElement());
            }
            // Init oracle
            SchemaAnalyzer samlSchemaAnalyser = SchemaAnalyzerFactory.getInstance(SchemaAnalyzerFactory.SAML);
            WrappingOracle wrappingOracle = new WrappingOracle(xmlDoc, payloadList, samlSchemaAnalyser);
            int max = wrappingOracle.maxPossibilities();
            Logging.getInstance().log(getClass(), "Wrapping oracle could generate " + max + " attack vectors.", Logging.INFO);
            // Save attack vectors
            for (int i = 0; i < max; i++) {
                try {
                    // Get vector
                    Document attackDoc = wrappingOracle.getPossibility(i);            
                    // Encode vector
                    String attackString = DomUtilities.domToString(attackDoc);
                    payloads.add(encode(attackString).getBytes());
                } catch (InvalidWeaknessException ex) {
                    Logging.getInstance().log(getClass(), "Failed to get XSW vector: " + i, Logging.ERROR);
                }
            }
            Logging.getInstance().log(getClass(), "Signature wrapping successfull.", Logging.INFO);
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
