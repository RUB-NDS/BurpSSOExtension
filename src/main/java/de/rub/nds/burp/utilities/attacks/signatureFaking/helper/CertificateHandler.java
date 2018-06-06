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
package de.rub.nds.burp.utilities.attacks.signatureFaking.helper;

import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.attacks.signatureFaking.exceptions.CertificateHandlerException;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CertificateHandler
{

    private X509Certificate certificate;

    private PublicKey originalPublicKey;

    private X509Certificate fakedCertificate;

    private KeyPair fakedKeyPair;

    private CertificateFactory certFactory;

    public CertificateHandler( final String cert )
        throws CertificateHandlerException
    {
        try
        {
            certFactory = CertificateFactory.getInstance( "X.509" );
            certificate =
                (X509Certificate) certFactory.generateCertificate( new ByteArrayInputStream( Base64.decodeBase64( cert ) ) );
            originalPublicKey = certificate.getPublicKey();
        }
        catch ( CertificateException e )
        {
            throw new CertificateHandlerException( e );
        }
    }

    public void createFakedCertificate()
        throws CertificateHandlerException
    {
        try
        {
            Logging.getInstance().log(getClass(), "Faking the found certificate", Logging.DEBUG);
            
            KeyPairGenerator kpg = KeyPairGenerator.getInstance( originalPublicKey.getAlgorithm() );
            kpg.initialize( ( (RSAPublicKey) certificate.getPublicKey() ).getModulus().bitLength() );
            fakedKeyPair = kpg.generateKeyPair();

            X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
            v3CertGen.setSubjectDN(certificate.getSubjectX500Principal());
            v3CertGen.setIssuerDN(certificate.getIssuerX500Principal());
            v3CertGen.setNotAfter(certificate.getNotAfter());
            v3CertGen.setNotBefore(certificate.getNotBefore());
            v3CertGen.setSerialNumber(new BigInteger(64, new Random()));
            v3CertGen.setSignatureAlgorithm(certificate.getSigAlgName());
            v3CertGen.setPublicKey(fakedKeyPair.getPublic());

            fakedCertificate = v3CertGen.generate(fakedKeyPair.getPrivate());
        }
        catch (CertificateEncodingException | SecurityException | SignatureException | InvalidKeyException | NoSuchAlgorithmException e )
        {
            throw new CertificateHandlerException( e );
        }
    }

    public PublicKey getOriginalPublicKey()
    {
        return originalPublicKey;
    }

    public void setOriginalPublicKey( PublicKey originalPublicKey )
    {
        this.originalPublicKey = originalPublicKey;
    }

    public X509Certificate getFakedCertificate()
    {
        return fakedCertificate;
    }

    public void setFakedCertificate( X509Certificate fakedCertificate )
    {
        this.fakedCertificate = fakedCertificate;
    }

    public KeyPair getFakedKeyPair()
    {
        return fakedKeyPair;
    }

    public void setFakedKeyPair( KeyPair fakedKeyPair )
    {
        this.fakedKeyPair = fakedKeyPair;
    }

    public String getFakedCertificateString()
        throws CertificateHandlerException
    {
        try
        {
            return new String( Base64.encodeBase64( fakedCertificate.getEncoded() ) );
        }
        catch ( CertificateEncodingException e )
        {
            throw new CertificateHandlerException( e );
        }
    }
}
