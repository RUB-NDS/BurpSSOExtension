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
public enum AsymmetricAlgorithm {
    
    RSA_OAEP_MGF1P("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"),
    RSA_PKCS1_15("RSA/ECB/PKCS1Padding", "http://www.w3.org/2001/04/xmlenc#rsa-1_5");

    private String javaName;

    private String uri;

    AsymmetricAlgorithm(String javaName, String uri) {
        this.javaName = javaName;
        this.uri = uri;
    }
    
    public static String[] getURIs() {
        return Arrays.stream(AsymmetricAlgorithm.values()).map(AsymmetricAlgorithm::getUri).toArray(String[]::new);
    }
    
    public static AsymmetricAlgorithm getByURI(String uri) {
        for(AsymmetricAlgorithm algo : AsymmetricAlgorithm.values()) {
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

}
