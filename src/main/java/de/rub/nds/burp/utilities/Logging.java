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

import burp.BurpExtender;
import java.io.PrintWriter;
import java.time.LocalTime;

/**
 *
 * @author Tim Guenther
 */
public class Logging {
    
    private static PrintWriter stdout = null;
    private static PrintWriter stderr = null;

    private Logging(){
        stdout = BurpExtender.stdout;
        stderr = BurpExtender.stderr;
    }
    
    private static class SingletonHolder {
        private static final Logging INSTANCE = new Logging();
    }

    public static Logging getInstance() {
        return SingletonHolder.INSTANCE;
    }
    
    public void log(String tag, String message, boolean error){
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        if(error){
            stdout.println(time+" - ["+tag+"]:\t"+"An Error happend, see Error tab.");
            stderr.println(time+" - ["+tag+"]:\t"+message);
        } else {
            stdout.println(time+" - ["+tag+"]:\t"+message);
        }
    }
    
    public void log(String tag, Exception e){
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        StackTraceElement[] stacktrace = e.getStackTrace();
        String trace = e.toString()+"\n";
        for(StackTraceElement ste : stacktrace){
            trace += "\t"+ste.toString()+"\n";
        }
        stdout.println(time+" - ["+tag+"]:\t"+"An Error happend, see Error tab.");
        stderr.println(time+" - ["+tag+"]:\t"+trace);
    }    
}
