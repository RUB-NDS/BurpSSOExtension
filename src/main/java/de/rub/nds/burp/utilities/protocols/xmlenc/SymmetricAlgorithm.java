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

import java.util.Arrays;

/**
 *
 * @author Juraj Somorovsky
 */
public enum SymmetricAlgorithm {
    
    AES128_CBC("AES/CBC/NoPadding", "http://www.w3.org/2001/04/xmlenc#aes128-cbc"),
    AES192_CBC("AES/CBC/NoPadding", "http://www.w3.org/2001/04/xmlenc#aes192-cbc"),
    AES256_CBC("AES/CBC/NoPadding", "http://www.w3.org/2001/04/xmlenc#aes256-cbc"),
    AES128_GCM("AES/GCM/NoPadding", "http://www.w3.org/2009/xmlenc11#aes128-gcm"),
    AES192_GCM("AES/GCM/NoPadding", "http://www.w3.org/2009/xmlenc11#aes192-gcm"),
    AES256_GCM("AES/GCM/NoPadding", "http://www.w3.org/2009/xmlenc11#aes256-gcm"),
    TRIPLEDES_CBC("DESede/CBC/NoPadding", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
    
    private String javaName;

    private String uri;

    SymmetricAlgorithm(String javaName, String uri) {
        this.javaName = javaName;
        this.uri = uri;
    }
    
    public static String[] getURIs() {
        return Arrays.stream(SymmetricAlgorithm.values()).map(SymmetricAlgorithm::getUri).toArray(String[]::new);
    }
    
    public static SymmetricAlgorithm getByURI(String uri) {
        for(SymmetricAlgorithm algo : SymmetricAlgorithm.values()) {
            if(algo.getUri().equals(uri)) {
                return algo;
            }
        }
        throw new IllegalArgumentException();
    }

    public String getJavaName() {
        return javaName;
    }

    public void setJavaName(String javaName) {
        this.javaName = javaName;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }
    
    public boolean isUsingPadding() {
        return (this == AES128_CBC || this == AES192_CBC || this == AES256_CBC || this == TRIPLEDES_CBC);
    }
    
    public int getIvLength() {
        switch (this) {
            case AES128_CBC:
            case AES192_CBC:
            case AES256_CBC:
                return 16;
            case AES128_GCM:
            case AES192_GCM:
            case AES256_GCM:
                return 12;
            default:
                return 8;
        }
    }
    
    public int getBlockSize() {
        if (this == TRIPLEDES_CBC) {
            return 8;
        } else {
            return 16;
        }
    }
    
    public String getSecretKeyAlgorithm() {
        if(this == TRIPLEDES_CBC) {
            return "TripleDES";
        } else {
            return "AES";
        }
    }

}
