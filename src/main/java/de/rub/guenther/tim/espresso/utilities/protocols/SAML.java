/*
 * Copyright (C) 2015 Tim Guenther
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package de.rub.guenther.tim.espresso.utilities.protocols;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.rub.nds.burp.utilities.Compression;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;

/**
 *
 * @author Tim Guenther
 */
public class SAML {
    
    private String saml = null;
    private String paramName = null;
    private String id = null;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    public SAML(){;
    }
    
    public SAML(String saml, String paramName){
        this.saml = saml;
        this.paramName = paramName;
        this.id = findID();
    }
    
    public SAML(IParameter param, IBurpExtenderCallbacks callbacks){
        this.paramName = param.getName();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        try {
            this.saml = decodeRedirectFormat(param.getValue());
        } catch (IOException ex) {
            Logger.getLogger(SAML.class.getName()).log(Level.SEVERE, null, ex);
        } catch (DataFormatException ex) {
            Logger.getLogger(SAML.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.id = findID();
    }
    
    
    public String getID(){
        return id;
    }
    
    private String findID(){
        Matcher m;
        Pattern p;
        switch (paramName) {
            case "SAMLRequest":
                p = Pattern.compile("ID=\"(.*?)\"");
                break;
            case "SAMLResponse":
                p = Pattern.compile("InResponseTo=\"(.*?)\"");
                break;
            default:
                return null;
        }
        
        m = p.matcher(saml);
        if(m.find()){
            return m.group(1);
        }
        return null;
    }
     
    private String decodeRedirectFormat(String input) throws IOException, DataFormatException {
        if(paramName.equals("SAMLRequest")){
            String urlDecoded = helpers.urlDecode(input);
            byte[] base64decoded = helpers.base64Decode(urlDecoded);
            byte[] decompressed = Compression.decompress(base64decoded);
            String result = new String(decompressed);
            return result;
        } else if(paramName.equals("SAMLResponse")){
            return helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(input)));
        }
        return null;
    }
    
    public String toString(){
        return id+" "+paramName+"="+saml;
    }
}
