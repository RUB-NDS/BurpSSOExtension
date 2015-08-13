/**
 * EsPReSSO - Extension for Processing and Recognition of Single Sign-On Protocols.
 * Copyright (C) 2015/ Tim Guenther and Christian Mainka
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

import de.rub.nds.burp.utilities.protocols.SAML;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;

/**
 * Analyse data for different encodings.
 * @author Tim Guenther
 * @version 1.0
 */
public abstract class Encoding {
    public static final int URL_ENCODED = 1;
    public static final int BASE64_ENCODED = 2;
    public static final int DEFLATED = 3;
    
    /**
     * Search for the encoding type of the data.
     * @param data The encoded data.
     * @return The integer flags for the encoding, -1 if no encoding is detected.
     */
    public static int getEncoding(String data){
        
        if(isURLEncoded(data)){
            return URL_ENCODED;
        } else if(isBase64Encoded(data)){
            return BASE64_ENCODED;
        } else try {
            if(isDeflated(data.getBytes("ASCII"))){
                return DEFLATED;
            }
        } catch (IOException ex) {
            Logger.getLogger(Encoding.class.getName()).log(Level.SEVERE, null, ex);
        }
        return -1;
    }
    
    /**
     * Check for URL encoding.
     * @param data The encoded data.
     * @return True if the encoding is URL Encoding, otherwise false.
     */
    public static boolean isURLEncoded(String data){
        boolean flag = true;
        //filter non ASCII chars
        if(!regex_contains("[^\\x00-\\x7F]", data)){
        try {
            URLDecoder.decode(data, "ASCII");
            Logger.getLogger(SAML.class.getName()).log(Level.SEVERE, null, data);
        } catch (UnsupportedEncodingException ex) {
            flag = false;
        }
        } else {
            flag = false;
        }
        String pattern = "(%[a-zA-Z0-9]{2})";
        return (flag && regex_contains(pattern, data));
    }
    
    /**
     * Check for Base64 encoding.<br>
     * Source for pattern see: {@code http://stackoverflow.com/questions/8571501/how-to-check-whether-the-string-is-base64-encoded-or-not}
     * @param data The encoded data.
     * @return True if the encoding is Base 64 Encoding, otherwise false.
     */
    public static boolean isBase64Encoded(String data){
        String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
        return regex_contains(pattern, data);
    }
    
    /**
     * Check for deflated.
     * @param data The compressed data.
     * @return True if the encoding is URL Encoding, otherwise false.
     * @throws java.io.IOException If the Compression class fails.
     */
    public static boolean isDeflated(byte[] data) throws IOException{
        try{
            Compression.decompress(data);
        } catch(DataFormatException e){
            return false;   
        }
        return true; 
    }
    
    private static boolean regex_contains(String pattern, String data){
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(data);
        return m.find();
    }
}
