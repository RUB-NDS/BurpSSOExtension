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
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Encoding;
import de.rub.nds.burp.utilities.Logging;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import org.w3c.dom.Document;
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
        
        private final String samlRequest = "SAMLRequest";
        private final String samlResponse = "SAMLResponse";        
    
        private XSWInputJDialog dialog;
        private IIntruderAttack attack;
        private int payloadIndex = 0;
        private IParameter samlContent = null;
        private String saml;
        private boolean isDeflated = false;
        private ArrayList<String> payloads;
        
        public XSWPayloadGenerator(IIntruderAttack attack) {
            this.attack = attack;
            if (!isSAML(attack.getRequestTemplate())) {
                Logging.getInstance().log(getClass(), "No SAML message", Logging.ERROR);
            }
            try {
                saml = decodeSamlParam(samlContent.getValue().replaceAll("§",""));
                dialog = new XSWInputJDialog(saml);
            } catch (IOException | DataFormatException ex) {
                Logging.getInstance().log(getClass(), "Failed to decode SAML message", Logging.ERROR);
            }
            generatePayloads();
            replaceValues();
        } 

        @Override
        public boolean hasMorePayloads() {
            return payloadIndex < payloads.size();
        }

        @Override
        public byte[] getNextPayload(byte[] bytes) {
            byte[] payload = helpers.stringToBytes(payloads.get(payloadIndex));
            payloadIndex++;
            return payload;
        }

        @Override
        public void reset() {
            payloadIndex = 0;
        }
        
        private void generatePayloads() {
            payloads = new ArrayList<>();
            try {
                // Init manager
                SignatureManager signatureManager = new SignatureManager();
                signatureManager.setDocument(DomUtilities.stringToDom(saml));
                List<Payload> payloadList = signatureManager.getPayloads();
                if (payloadList.size() > 0) {
                    // TODO
                } else {
                    Logging.getInstance().log(getClass(), "No Payload found", Logging.INFO);
                }
                // Init oracle
                Document samlDoc = signatureManager.getDocument();
                SchemaAnalyzer samlSchemaAnalyser = SchemaAnalyzerFactory.getInstance(SchemaAnalyzerFactory.SAML);
                WrappingOracle wrappingOracle = new WrappingOracle(samlDoc, payloadList, samlSchemaAnalyser);
                // Save attack vectors
                payloads.add(saml); // Remove
                payloads.add(Integer.toString(wrappingOracle.maxPossibilities())); // Remove
                for (int i = 0; i < wrappingOracle.maxPossibilities(); i++) {
                    Document attackDoc = wrappingOracle.getPossibility(i);
                    String attackString = DomUtilities.domToString(attackDoc);
                    payloads.add(attackString);
                }
            } catch (SAXException | InvalidWeaknessException ex) {
                Logging.getInstance().log(getClass(), "Failed to generate XSW vectors", Logging.ERROR);
            }            
        }
        
        private void replaceValues() {
            // TODO
            Collection collection = dialog.getValuePairs().values();
            Iterator iterator = collection.iterator();
            while(iterator.hasNext()) {
                Map.Entry pair = (Map.Entry)iterator.next();
            }
        }
        
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
        
        private String decodeSamlParam(String samlParam) throws IOException, DataFormatException {
            byte [] tmp;
            if(Encoding.isURLEncoded(samlParam)) {
                samlParam = helpers.urlDecode(samlParam);
            }
            if(Encoding.isBase64Encoded(samlParam)) {
                tmp = helpers.base64Decode(samlParam);
            } else {
                tmp = samlParam.getBytes();
            }
            isDeflated = false;
            if (Encoding.isDeflated(tmp)) {
                tmp = Compression.decompress(tmp);
                isDeflated = true;
            }
            return new String(tmp);
        }
        
        private byte[] encodeSamlParam(String samlParam) throws IOException, DataFormatException {
            byte[] tmp = samlParam.getBytes();
            if (isDeflated == true) {
                tmp = Compression.compress(tmp);
            }
            tmp = helpers.base64Encode(tmp).getBytes();
            tmp = helpers.urlEncode(tmp);
            return tmp;
        }
    }
}
