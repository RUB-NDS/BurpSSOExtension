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

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

/**
 * Helper class for the class Table.
 * 
 * @author Nurullah Erinola
 */
public class TableModel extends AbstractTableModel{
    
    private ArrayList<TableEntry> list;
    private String[] columnNames = {"xPath", "Current value", "New value"};

    /**
     * Construct a new Table Helper
     */
    public TableModel() {
        list = new ArrayList<>();
    }

    /**
     * Get the table list.
     * @return The list saved during the construction.
     */
    public ArrayList<TableEntry> getTableList(){
        return list;
    }
    
    public TableEntry getTableEntry(int row) {
        return list.get(row);
    }
    
    /**
     * Add a row to the list and the table.
     * @param entry The new row.
     */
    public void addRow(TableEntry entry){
        list.add(entry);
        int tmp = list.size()-1;
        fireTableRowsInserted(tmp, tmp);
    }
    
    /**
     * Remove all entries from the table list.
     */
    public void clearAll(){
        list.clear();
        fireTableDataChanged();
    }
    
    /**
     * Remove one entrie from the table list.
     * @param row The removed row.
     */
    public void remove(int row){
        list.remove(row);
        int tmp = list.size()-1;
        fireTableRowsDeleted(tmp, tmp);
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
     * @return Number of columns.
     */
    @Override
    public int getColumnCount()
    {
        return columnNames.length;
    }

    /**
     * Get the name of the column.
     * @param columnIndex Index of the column.
     * @return The name of the column.
     */
    @Override
    public String getColumnName(int columnIndex)
    {
        return columnNames[columnIndex];
    }

    /**
     * Get the class of the column.
     * @param columnIndex Index of the column.
     * @return The class of the column.
     */
    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
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
                return entry.getXPath();
            case 1:
                return entry.getCurrentValue();
            case 2:
                return entry.getNewValue();
            default:
                return null;
        }
    }
    
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }
}
