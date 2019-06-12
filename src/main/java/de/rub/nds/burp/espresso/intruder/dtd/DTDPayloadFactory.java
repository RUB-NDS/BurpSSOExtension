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
package de.rub.nds.burp.espresso.intruder.dtd;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import de.rub.nds.burp.utilities.Compression;
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.XMLHelper;
import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Node;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * DTD Payload Generator.
 *
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

        private DTDInputJDialog dialog;
        private IIntruderAttack attack;
        private ArrayList<String> rawDtds;
        private ArrayList<String> dtds;
        private int payloadIndex;

        public DTDPayloadGenerator(IIntruderAttack attack) {
            this.attack = attack;
            // setd dtds to raw vectors (no protocol handlers)
            parseVectors();
            dialog = new DTDInputJDialog(rawDtds.size());
            // fill in selected protcol handlers and listeners
            generateDTDs();
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

        private void parseVectors() {
            try {
                rawDtds = new ArrayList<>();
                Document doc = XMLHelper.stringToDom(IOUtils.toString(getClass().getClassLoader().getResource("dtd_configs.xml"), "UTF-8"));
                List<Node> vectors =  (List<Node>) DomUtilities.evaluateXPath(doc, "//attackvectors[@intruderVector='true']/attackvector/directMessage");
                for (int j = 0; j < vectors.size(); j++) {
                    String vector = vectors.get(j).getTextContent();
                    rawDtds.add(vector);
                }
            } catch (IOException | XPathExpressionException ex) {
                Logging.getInstance().log(getClass(), ex);
            }
        }

        private void generateDTDs() {
            dtds = new ArrayList<>();
            ArrayList<String> listeners = dialog.getListeners();
            ArrayList<String> protocols = dialog.getProtocols();
            int listenerIndex = 0;
            for (String rawDtd : rawDtds) {
                for (String protocol : protocols) {
                    String vector = rawDtd;
                    vector = vector.replace(helperURL, protocol + listeners.get(listenerIndex));
                    vector = vector.replace(listenURL, protocol + listeners.get(listenerIndex));
                    dtds.add(encode(vector));
                    listenerIndex++;
                }
            }

        }

        private String encode(String vector) {
            byte[] tmp = vector.getBytes();
            if (dialog.getEnflateChoice()) {
                try {
                    tmp = Compression.compress(tmp);
                } catch (IOException ex) {
                    Logging.getInstance().log(getClass(), "failed to compress param", Logging.ERROR);
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
