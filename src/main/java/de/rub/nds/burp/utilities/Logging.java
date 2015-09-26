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
import de.rub.nds.burp.espresso.gui.UIOptions;
import java.io.PrintWriter;
import java.time.LocalTime;

/**
 * The extension internal logging.
 * @author Tim Guenther
 * @version 1.0
 * 
 * <b>ATTENTION!</b><br>
 * Based on the internal architecture of Burp Suite, the first called class is
 * {@link burp.BurpExtender}, this class initialises the {@link java.io.PrintWriter}.
 * So <b>NEVER</b> call the Logging before this initialisation.
 */
public class Logging {
    
    private static PrintWriter stdout = null;
    private static PrintWriter stderr = null;
    
    /**
     * {@value #ERROR}
     */
    public static final int ERROR = 1;
    /**
     * {@value #INFO}
     */
    public static final int INFO = 2;
    /**
     * {@value #DEBUG}
     */
    public static final int DEBUG = 3;

    //Singleton Design Pattern.
    private Logging(){
        stdout = BurpExtender.getStdOut();
        stderr = BurpExtender.getStdErr();
    }
    
    //Create a only one instace.
    private static class SingletonHolder {
        private static final Logging INSTANCE = new Logging();
    }

    /**
     * Get the Instance of the Logger.
     * @return A Logging instance.
     */
    public static Logging getInstance() {
        return SingletonHolder.INSTANCE;
    }
    
    /**
     * Log a specific message on a logging level.
     * @param c The calling class.
     * @param message The message to log.
     * @param log_type The logging type. ERROR = {@value #ERROR}, INFO = 
     * {@value #INFO}, DEBUG = {@value #DEBUG}
     */
    public void log(Class c, String message, int log_type){
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        switch(log_type){
            case ERROR:
                stdout.println("[E] "+time+" - ["+c.getName()+"]:\t"+"Error, see Errors tab.");
                stderr.println("[E] "+time+" - ["+c.getName()+"]:\t"+message);
                break;
            case INFO:
                if(UIOptions.getLoggingLevel() == 0 || UIOptions.getLoggingLevel() == 2){
                    stdout.println("[I] "+time+" - ["+c.getName()+"]:\t"+message);
                }
                break;
            case DEBUG:
                if(UIOptions.getLoggingLevel() == 1 || UIOptions.getLoggingLevel() == 2){
                    stdout.println("[D] "+time+" - ["+c.getName()+"]:\t"+message);
                }
                break;
        }
    }
    
    /**
     * Log an error on level ERROR.
     * @param c The calling class.
     * @param e The thrown exception.
     */
    public void log(Class c, Exception e){
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        StackTraceElement[] stacktrace = e.getStackTrace();
        String trace = e.toString()+"\n";
        for(StackTraceElement ste : stacktrace){
            trace += "\t"+ste.toString()+"\n";
        }
        stdout.println("[E] "+time+" - ["+c.getName()+"]:\t"+"Error, see Errors tab.");
        stderr.println("[E] "+time+" - ["+c.getName()+"]:\t"+trace);
    }    
}
