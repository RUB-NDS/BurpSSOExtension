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
package de.rub.nds.burp.utilities;


import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import wsattacker.library.xmlutilities.namespace.NamespaceResolver;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.*;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Help pretty print XML content
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class XMLHelper {

    /**
    * Create an indention to pretty print the XML.
    * Attention: Pretty printed XML doesn't work for requests. 
    * @param input The XML raw data.
    * @param indent The indents width.
    * @return Indented XML or original input if an Exception is thrown internally.
    */

    public static String format(String input, int indent) {
        // javax.xml.transform.Transformer does not keep DTDs and always expands
        // entity references defined in inline DTDs - so we do not pretty-print those
        if (input.toUpperCase().contains("DOCTYPE")) {
            Logging.getInstance().log(XMLHelper.class,"XML contains inline DTD, skip pretty printing", Logging.DEBUG);
            return input;
        }
        try {
            Source xmlInput = new StreamSource(new StringReader(input));
            StringWriter stringWriter = new StringWriter();
            StreamResult xmlOutput = new StreamResult(stringWriter);

            Transformer transformer = getSecureTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, input.startsWith("<?xml") ? "yes" : "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", String.valueOf(indent));
            transformer.transform(xmlInput, xmlOutput);
            return xmlOutput.getWriter().toString();
        } catch (IllegalArgumentException | TransformerException e) {
            Logging.getInstance().log(XMLHelper.class, e);
            return input;
        }
    }

    public static String docToString(Document doc) {
        Source docInput = new DOMSource(doc);
        return sourceToString(docInput, false);
    }

    public static String nodeToString(Node node) {
        Source docInput = new DOMSource(node);
        return sourceToString(docInput, true);
    }

    private static String sourceToString(Source domSource, boolean omitPreamble) {
        try {
            StringWriter stringWriter = new StringWriter();
            StreamResult xmlOutput = new StreamResult(stringWriter);

            Transformer transformer = getSecureTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            if (omitPreamble) {
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            }

            transformer.transform(domSource, xmlOutput);
            return xmlOutput.getWriter().toString();
        } catch (TransformerConfigurationException ex ) {
            return "<error>Failed to configure TransformerFactory:" + ex.getMessage() + "</error>";
        } catch (TransformerException ex) {
            return "<error>Failed to transform document.</error>";
        }
    }

    private static Transformer getSecureTransformer() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

		Transformer transformer = transformerFactory.newTransformer();
		return transformer;
    } 

    public static Document stringToDom (String xmlString) {
        try {
            InputSource input = new InputSource(new StringReader(xmlString));
            DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
            documentFactory.setNamespaceAware(true);
            documentFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder builder = documentFactory.newDocumentBuilder();
            Document dom = builder.parse(input);
            return dom;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Logging.getInstance().log(XMLHelper.class, e);
            return stringToDom("<error>Failed to parse input XML</error>");
        }
    }

    public static Node getElementByXPath (Document doc, String xPath) {
        try {
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();
            XPathExpression expr = xpath.compile(xPath);
            Node node = (Node) expr.evaluate(doc, XPathConstants.NODE);
            return node;
        } catch (XPathExpressionException e) {
            Logging.getInstance().log(XMLHelper.class, e);
            return null;
        }
    }

    public static List<Node> getElementsByXPath (Document doc, String xPath, Map<String, String> nsMap) throws XPathExpressionException {
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();

            NamespaceResolver nsr = new NamespaceResolver(doc);
            if (nsMap != null) {
                nsMap.forEach((k,v) -> nsr.addNamespace(k,v));
            }
            xpath.setNamespaceContext(nsr);

            XPathExpression expr = xpath.compile(xPath);
            NodeList nodes = (NodeList)expr.evaluate(doc, XPathConstants.NODESET);
            List<Node> nodelist = new ArrayList();
            for(int i = 0; i < nodes.getLength(); ++i) {
                nodelist.add(nodes.item(i));
            }

            return nodelist;
    }
}
