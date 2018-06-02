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
package de.rub.nds.burp.espresso.intruder;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IParameter;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.XMLHelper;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * DTD Payload Generator.
 * @author Nurullah Erinola
 */
public class DTDPayloadFactory implements IIntruderPayloadGeneratorFactory {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;  
    
    public DTDPayloadFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }
    
    @Override
    public String getGeneratorName() {
        return "DTD Payloads";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new DTDPayloadGenerator(attack);
    }
    
    class DTDPayloadGenerator implements IIntruderPayloadGenerator {

        private final String listenURL = "§tf_listenURL§";
        private final String helperURL = "§tf_helperURL§";
        private final String targetFILE = "§tf_targetFILE§";
        private final String samlRequest = "SAMLRequest";
        private final String samlResponse = "SAMLResponse";
        
        private InputJDialog dialog;
        private String listener = "listener.org";
        private String protocol = "http";
        
        private IIntruderAttack attack;
        private ArrayList<String> dtds;
        private int payloadIndex;
        private boolean isSamlRequest = false;
        private boolean isSamlResponse = false;
        
        public DTDPayloadGenerator(IIntruderAttack attack) {
            this.attack = attack;
            isSAML();
            dialog = new InputJDialog();
            readDTDs();
        }
        
        @Override
        public boolean hasMorePayloads() {
            return payloadIndex < dtds.size();
        }

        @Override
        public byte[] getNextPayload(byte[] bytes) {
            byte[] payload = helpers.stringToBytes(dtds.get(payloadIndex));
            payloadIndex++;
            return payload;
        }

        @Override
        public void reset() {
            payloadIndex = 0;
        }
        
        private void readDTDs() {
            try {
                dtds = new ArrayList<>();
                Document doc = XMLHelper.stringToDom(IOUtils.toString(getClass().getClassLoader().getResource("dtd_configs.xml"),"UTF-8"));
                NodeList configs = doc.getElementsByTagName("config");
                for (int i = 0; i < configs.getLength(); i++) {
                    Element config = (Element) configs.item(i);
                    if(config.getElementsByTagName("helperURL").item(0).getTextContent().equalsIgnoreCase("TRUE")
                            || config.getElementsByTagName("attackListenerURL").item(0).getTextContent().equalsIgnoreCase("TRUE")) {
                        NodeList vectors = config.getElementsByTagName("directMessage");
                        for (int j = 0; j < vectors.getLength(); j++) {
                            String vector = vectors.item(j).getTextContent();
                            //Replacing
                            protocol = dialog.getProtocol();
                            listener = dialog.getListener();
                            vector = vector.replace(targetFILE, "file:///etc/hostname");
                            vector = vector.replace(helperURL, protocol+listener+"/helper.dtd");
                            vector = vector.replace(listenURL, protocol+listener);
                            dtds.add(encode(vector));
                        }
                    }
                }
            } catch (IOException ex) {
                Logging.getInstance().log(getClass(), ex);
            }
        }
        
        private void isSAML() {
            IParameter samlContent = helpers.getRequestParameter(attack.getRequestTemplate(), samlRequest);
            if (null != samlContent){
                isSamlRequest = true;
            }
            samlContent = helpers.getRequestParameter(attack.getRequestTemplate(), samlResponse);
            if (null != samlContent){
                isSamlResponse = true;
            }
        }
        
        private String encode(String vector) {
            byte[] tmp = vector.getBytes();
            if (isSamlResponse) {
                try {
                    tmp = Compression.compress(tmp);
                    tmp = helpers.base64Encode(tmp).getBytes();
                    tmp = helpers.urlEncode(tmp);
                } catch (IOException ex) {
                    tmp = vector.getBytes();
                    Logging.getInstance().log(getClass(), "failed to re-encode SAML param", Logging.ERROR);
                }
            }
            if (isSamlRequest) {
                tmp = helpers.base64Encode(tmp).getBytes();
                tmp = helpers.urlEncode(tmp);
            }
            return new String(tmp);
        }
    }
}
