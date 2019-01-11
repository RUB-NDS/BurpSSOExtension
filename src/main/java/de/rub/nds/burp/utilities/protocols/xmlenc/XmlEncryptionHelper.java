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
package de.rub.nds.burp.utilities.protocols.xmlenc;

import de.rub.nds.burp.utilities.ByteArrayHelper;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 */
public class XmlEncryptionHelper {

    private byte[] symmetricKey;

    public String encryptKey(String certificate, AsymmetricAlgorithm algorithm) throws CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        RSAPublicKey publicKey = getPublicKey(certificate);
        if (publicKey != null) {
            if (algorithm == AsymmetricAlgorithm.RSA) {
                // this algorithm is only supported in Bouncy Castle 
                BigInteger sk = new BigInteger(symmetricKey);
                BigInteger biResult = sk.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
                byte[] result = biResult.toByteArray();
                if(result[0] == 0) {
                    result = Arrays.copyOfRange(result, 1, result.length);
                }
                return Base64.getEncoder().encodeToString(result);
            } else {
                Cipher cipher = Cipher.getInstance(algorithm.getJavaName());
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] result = cipher.doFinal(symmetricKey);
                return Base64.getEncoder().encodeToString(result);
            }
        } else {
            return "";
        }
    }

    public static RSAPublicKey getPublicKey(String certificate) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection c = cf.generateCertificates(new ByteArrayInputStream(certificate.getBytes()));
        Iterator i = c.iterator();
        RSAPublicKey publicKey = null;
        while (i.hasNext()) {
            Certificate cert = (Certificate) i.next();
            publicKey = (RSAPublicKey) cert.getPublicKey();
        }
        return publicKey;
    }

    public String encryptData(byte[] data, SymmetricAlgorithm algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm.getJavaName());
        SecretKey secretKey = new SecretKeySpec(symmetricKey, algorithm.getSecretKeyAlgorithm());
        byte[] result;
        if(!algorithm.isUsingGCMMode()) {          
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[algorithm.getIvLength()]);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            result = ByteArrayHelper.concatenate(ivParameterSpec.getIV(), cipher.doFinal(data));
        } else {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, new byte[algorithm.getIvLength()]);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            result = ByteArrayHelper.concatenate(gcmParameterSpec.getIV(), cipher.doFinal(data));        
        }     
        return Base64.getEncoder().encodeToString(result);
    }

    public byte[] computePadding(byte[] data, SymmetricAlgorithm algorithm) {
        if (algorithm.isUsingPadding()) {
            int length = algorithm.getBlockSize() - (data.length % algorithm.getBlockSize());
            byte[] result = new byte[length];
            result[length - 1] = (byte) length;
            return result;
        } else {
            return new byte[0];
        }
    }

    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(byte[] symmetricKey) {
        this.symmetricKey = symmetricKey;
    }
}
