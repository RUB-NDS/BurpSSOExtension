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
package de.rub.nds.burp.utilities.table.ssoHistory;

import de.rub.nds.burp.utilities.Logging;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

/**
 * Helper class for the class Table.
 * @author Tim Guenther
 * @version 1.0
 */
public class TableHelper extends AbstractTableModel{
    
    private ArrayList<TableEntry> list;
    private String[] colName = {"#","SSO Protocol","Host","Method","URL","Token","Time","Length","Comment"};

    /**
     * Construct a new Table Helper
     * @param list A list of table entries.
     */
    public TableHelper(ArrayList<TableEntry> list) {
        this.list = list;
    }

    /**
     * Get the table list.
     * @return The list saved during the construction.
     */
    public ArrayList<TableEntry> getTableList(){
        return list;
    }
    
    /**
     * Add a row to the list and the table.
     * @param entry The new row.
     * @return True if successfully, false otherwise.
     */
    public boolean addRow(TableEntry entry){
        try{
            int row = list.size();
            list.add(entry);
            fireTableRowsInserted(row,row);
        } catch(Exception e) {
            return false;
        }
        return true;
    }
    
    /**
     * Remove all entries from the table list.
     * @return True if all entries removed, false otherwise.
     */
    public boolean clear(){
        try{
            list.clear();
            fireTableDataChanged();
        } catch(Exception e) {
            return false;
        }
        return true;
    }
    
    /**
     * Get the number of rows.
     * @return Number of rows.
     */
    @Override
    public int getRowCount()
    {
        return list.size();
    }

    /**
     * 
     * @return Number of columns. (9)
     */
    @Override
    public int getColumnCount()
    {
        return 9;
    }

    /**
     * Get the name of the column.
     * @param columnIndex Index of the column.
     * @return The name of the column.
     */
    @Override
    public String getColumnName(int columnIndex)
    {
        try {
            return colName[columnIndex];
        } catch (Exception e) {
            Logging.getInstance().log(getClass(), e);
            return "";
        }
    }

    /**
     * Get the class of the column.
     * @param columnIndex Index of the column.
     * @return The class of the column.
     */
    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return Integer.class;
            default:
                return String.class;
        }
    }

    /**
     * Get the value at a position.
     * @param rowIndex The row.
     * @param columnIndex The column.
     * @return Value for the specified entry. Null if not found.
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        TableEntry entry = list.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return entry.getCounter();
            case 1:
                return entry.getProtocol();
            case 2:
                return entry.getHost();
            case 3:
                return entry.getMethod();
            case 4:
                return entry.getUrl();
            case 5:
                return entry.getToken() ;   
            case 6:
                return entry.getTime();
            case 7:
                return entry.getLength();
            case 8:
                return entry.getComment();
            default:
                return null;
        }
    }
}
