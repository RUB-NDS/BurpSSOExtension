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

import de.rub.nds.burp.espresso.gui.UIHistory;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import java.util.ArrayList;
import java.util.Iterator;
import javax.swing.JTable;

/**
 * A Table for the SSOHistory.
 * @author Tim Guenther
 * @version 1.0
 */
public class Table extends JTable{
    private TableHelper th;
    private ArrayList<TableEntry> list;
    private String name;
    private String id;
    
    /**
     * Create a new Table.
     * @param th The helper to organise your table entries.
     * @param name The table name.
     * @param id The request id.
     */
    public Table(TableHelper th, String name, String id)
    {
        super(th);
        this.th = th;
        this.list = th.getTableList();
        this.name = name;
        this.id = id;
    }

    /**
     * 
     * @return The name of the table. 
     */
    public String getName(){
        return name;
    }
    
    /**
     * 
     * @return The request id of the table.
     */
    public String getID(){
        return id;
    }
    
    /**
     * 
     * @return The TableHelper related to the table. 
     */
    public TableHelper getTableHelper(){
        return th;
    }

    /**
     * 
     * @return Get a list of table entries.
     */
    public ArrayList<TableEntry> getTableList(){
        return list;
    }
    
    public TableEntry getTableEntry(int i){
        return list.get(i);
    }

    /**
     * Controls the current displayed item in the detail view.
     * The item is displayed below the SSO history window.
     * @param row The current row.
     * @param col The current column.
     * @param toggle Should the entry be toggled. 
     * @param extend Should the entry be extended.
     */
    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        // show the entry for the selected row
        TableEntry entry = list.get(row);
        UIHistory.requestViewer.setMessage(entry.getFullMessage().getRequest(), true);
        UIHistory.responseViewer.setMessage(entry.getFullMessage().getResponse(), false);
        UIHistory.currentlyDisplayedItem = entry.getFullMessage();

        super.changeSelection(row, col, toggle, extend);
    }
    
    public void update(){
        SSOProtocol sso = list.get(0).getSSOProtocol();
        ArrayList<SSOProtocol> ssoList = sso.getProtocolFlow();
        list.clear();
        for (Iterator<SSOProtocol> it = ssoList.iterator(); it.hasNext();) {
            sso = it.next();
            th.addRow(sso.toTableEntry());
        }
    }
}
