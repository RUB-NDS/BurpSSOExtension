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
package de.rub.nds.burp.utilities.table.xsw;

/**
 * A table entry for the class Table.
 * 
 * @author Nurullah Erinola
 */
public class TableEntry {
    
    private String counter;
    private String xPath;
    private String currentValue;
    private String newValue;

    /**
     * Construct a new table entry.
     */
    public TableEntry(int counter, String xPath, String currentValue, String newValue) {
        this.counter = Integer.toString(counter);
        this.xPath = xPath;
        this.currentValue = currentValue;
        this.newValue = newValue;
    }

    public String getCounter() {
        return counter;
    }
    
    public String getXPath() {
        return xPath;
    }
    
    public String getCurrentValue() {
        return currentValue;
    }
    
    public String getNewValue() {
        return newValue;
    }
    
}
