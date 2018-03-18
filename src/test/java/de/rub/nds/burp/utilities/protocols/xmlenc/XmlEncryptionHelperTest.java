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
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 */
public class XmlEncryptionHelperTest {

    String certificate = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDXTCCAkWgAwIBAgIJAIxP8J/SewB+MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n"
            + "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
            + "aWRnaXRzIFB0eSBMdGQwHhcNMTgwMzA0MTQ1MDQxWhcNMzExMTExMTQ1MDQxWjBF\n"
            + "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n"
            + "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
            + "CgKCAQEA7dt6PNOO7kHRNu+IiES/e70IX3QRpZGNrj2RTVWf66fRQVeFbnnwXFxn\n"
            + "QU4z+YI3mVNtnSd8wdox2kvz9tbSNO+GzMvJzoKGInXB5rAWnloUJ8+sEL/SZ1i0\n"
            + "M87k5/IBr+x1DQ23fOy0Q6CeTNkrC6KXKsOX+Mi5RQq+M1cVHmO4JhmGJUuJrdcG\n"
            + "VEzSSE0oDfOu++fCuArcDJtN/G5EBvkKVJUnOfR1/KaV0AkpI7RS2KgaYlMi2Hj/\n"
            + "dueH8DtUdlMXuQpCoByD3ZPlwVRJ1JZcRPFHTO4rmw620as4sixthkzHnQeTGnq/\n"
            + "etuKLX0UUSwCmOXdysGrKaOBACKgvwIDAQABo1AwTjAdBgNVHQ4EFgQU/cx/Xzz/\n"
            + "/TIUftk46Goyypegf2MwHwYDVR0jBBgwFoAU/cx/Xzz//TIUftk46Goyypegf2Mw\n"
            + "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAh824gQhX6vMlL85dcbcb\n"
            + "GPcuzwZASbTbdWaDTbSHbRW5Na5jiJo/eeSXmrFxj3G8Y5186rysIEsz0c0YlyIp\n"
            + "jF2kTjJrhWKzcGRVzBA07j3juXpJ2QA61ILoKjOIioebZSfy0pQ0VgIbEsA5BVzZ\n"
            + "SclOatoWM/WqgtlveyVKU5zjOMysf/HLf9qBPLLdB71vf/n1GYbLKAcH9X4HD5M+\n"
            + "zSLLPIRs0XFlGNXNJYR2ZojYk9ycLBsunwGYEflJRTMl+oQBPDOYMCemcxM3PWR8\n"
            + "dsVM3xBxbS3RxIt61mZr5xj4BBCsci49dhNcZ6rTqYMISFoY9D9rzQiBV4ULD+Wc\n"
            + "kQ==\n"
            + "-----END CERTIFICATE-----";
    
    XmlEncryptionHelper xmlEncryptionHelper;

    public XmlEncryptionHelperTest() {
        xmlEncryptionHelper = new XmlEncryptionHelper();
        xmlEncryptionHelper.setSymmetricKey(new byte[16]);
    }

    /**
     * Test of encryptKey method, of class XmlEncryptionHelper.
     * @throws java.lang.Exception
     */
    @Test
    public void testEncryptKey() throws Exception {
        String result = xmlEncryptionHelper.encryptKey(certificate, AsymmetricAlgorithm.RSA_OAEP_MGF1P);
        assertNotNull(result);
        assertNotEquals("", result);
    }
    
    /**
     * Test of encryptKey method, of class XmlEncryptionHelper.
     * @throws java.lang.Exception
     */
    @Test
    public void testEncryptKeyPlainRSA() throws Exception {
        byte[] key = new byte[]{0, 0, 0, 7};
        xmlEncryptionHelper.setSymmetricKey(key);
        String result = xmlEncryptionHelper.encryptKey(certificate, AsymmetricAlgorithm.RSA);
        System.out.println(result);
        assertNotNull(result);
        assertNotEquals("", result);
        
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm.RSA.getJavaName());
        cipher.init(Cipher.ENCRYPT_MODE, XmlEncryptionHelper.getPublicKey(certificate));
        String expected = Base64.getEncoder().encodeToString(cipher.doFinal(key));
        assertEquals(expected, result);
    }
    
    @Test
    public void testEncryptData() throws Exception {
        SymmetricAlgorithm algorithm = SymmetricAlgorithm.AES128_CBC;
        byte[] xml = "<test></test>".getBytes();
        byte[] padding = xmlEncryptionHelper.computePadding(xml, algorithm);
        byte[] data = ByteArrayHelper.concatenate(xml, padding);
        String result = xmlEncryptionHelper.encryptData(data, algorithm);
        assertNotNull(result);
        assertNotEquals("", result);
    }

}
