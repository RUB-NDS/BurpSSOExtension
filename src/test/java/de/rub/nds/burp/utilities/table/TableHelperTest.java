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
package de.rub.nds.burp.utilities.table;

import burp.IHttpRequestResponsePersisted;
import java.util.ArrayList;
import junit.framework.TestCase;

/**
 *
 * @author Tim Guenther
 */
public class TableHelperTest extends TestCase {
    
    public TableHelperTest(String testName) {
        super(testName);
    }

    /**
     * Test of getTableList method, of class TableHelper.
     */
    public void testGetTableList() {
        System.out.println("getTableList");
        ArrayList<TableEntry> expResult = new ArrayList<TableEntry>();
        TableHelper instance = new TableHelper(expResult);
        ArrayList<TableEntry> result = instance.getTableList();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getRowCount method, of class TableHelper.
     */
    public void testGetRowCount() {
        System.out.println("getRowCount");
        TableHelper instance = new TableHelper(new ArrayList<TableEntry>());
        int expResult = 0;
        int result = instance.getRowCount();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of getColumnCount method, of class TableHelper.
     */
    public void testGetColumnCount() {
        System.out.println("getColumnCount");
        TableHelper instance = new TableHelper(new ArrayList<TableEntry>());
        int expResult = 10;
        int result = instance.getColumnCount();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        // fail("The test case is a prototype.");
    }
    
}
