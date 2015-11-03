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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.Base64.Decoder;
import junit.framework.TestCase;

/**
 *
 * @author ackbar
 */
public class EncodingTest extends TestCase {
    
    public EncodingTest(String testName) {
        super(testName);
    }


    /**
     * Test of isURLEncoded method, of class EncodingChecker.
     */
    public void testIsURLEncoded() {
        System.out.println("isURLEncoded");
        String data = "This%20is%20a%20test%20string%20with%20special%20chars%20like%20ths%3A%20%2f@%5E%26%2a%28%28%29%7B%7D%7B%3A%3B";
        boolean result = Encoding.isURLEncoded(data);
        assertTrue(result);
        
        data = " /!@#$*()[]{}";
        result = Encoding.isURLEncoded(data);
        assertFalse(result);
    }

    /**
     * Test of isBase64Encoded method, of class EncodingChecker.
     */
    public void testIsBase64Encoded() {
        System.out.println("isBase64Encoded");
        
        String data = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdpdGggc3BlY2lhbCBjaGFycyBsaWtlIHRoczogL0BeJiooKCl7fXs6Ow==";
        boolean result = Encoding.isBase64Encoded(data);
        assertTrue(result);
        
        String data1 = "This is a test string with special chars like ths: /@^&*((){}{:;";
        boolean result1 = Encoding.isBase64Encoded(data1);
        assertFalse(result1);
        
        String data2 = "This%20is%20a%20test%20string%20with%20special%20chars%20like%20ths%3A%20%2f@%5E%26%2a%28%28%29%7B%7D%7B%3A%3B";
        boolean result2 = Encoding.isBase64Encoded(data2);
        assertFalse(result2);
        
    }

    /**
     * Test of isDeflated method, of class EncodingChecker.
     */
    public void testIsDeflated() {
        System.out.println("isDeflated");
        String data = "fZFba8MwDIX%2FStB7c11a19QpYaNQ2GCsl4e9DDdR2rDEziy79OfP9MI6BnsUOp%2BOdDSbn%2FouOKKhVisBSRhDgKrSdav2AjbrxYjBvJiR7Lt04KWzB%2FWGXw7JBh5UxC8dAc4oriW1xJXskbit%2BKp8eeZpGPPBaKsr3UFQEqGx3upRK3I9mhWaY1vhUtV4EuDNS2tNu3MWLwq%2Fxh%2FJQpsKz6sIaGRHCMHyScAHm%2BwaTOo8G0uZxslDlu8mdTOOMzaVjE0bL6NXSdQe8Qckcn40WamsAE%2Flo5iNknSdpDxPeRaHLJu%2BQ7C9JeTvgWse%2FAyb%2ByD%2Bz0HerofiYO3Ao8ijW206JKf2IQ1hpftIadPLbq0%2FUc2ie6PiWv7%2BQ%2FEN";
        try {
            data = URLDecoder.decode(data, "ASCII");
        } catch (UnsupportedEncodingException ex) {
            fail(ex.toString());
        }
        Decoder d = Base64.getDecoder();
        byte[] bin_data = d.decode(data);
        
        boolean result = false;
        try {
            result = Encoding.isDeflated(bin_data);
        } catch (IOException ex) {
            fail(ex.toString());
        }
        
        assertTrue(result);
    }
    
}
