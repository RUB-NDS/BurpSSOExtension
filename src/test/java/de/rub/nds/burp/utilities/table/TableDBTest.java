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
package de.rub.nds.burp.utilities.table;

import junit.framework.TestCase;

/**
 *
 * @author Tim Guenther
 */
public class TableDBTest extends TestCase {
    
    public TableDBTest(String testName) {
        super(testName);
    }

    /**
     * Test of getTable method, of class TableDB.
     */
    public void testGetTable_String() {
        System.out.println("getTable");
        String id = "123";
        Table expResult = new Table(new TableHelper(null),"testName",id);
        TableDB.addTable(expResult);
        Table result = TableDB.getTable(id);
        assertEquals(expResult.getID(), result.getID());
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getTable method, of class TableDB.
     */
    public void testGetTable_int() {
        System.out.println("getTable");
        int index = 0;
        Table expResult = new Table(new TableHelper(null),"testName","123");
        TableDB.addTable(expResult);
        Table result = TableDB.getTable(index);
        assertEquals(expResult.getID(), result.getID());
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of addTable method, of class TableDB.
     */
    public void testAddTable() {
        System.out.println("addTable");
        Table t = null;
        assertTrue(TableDB.addTable(t));
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }
    
}
