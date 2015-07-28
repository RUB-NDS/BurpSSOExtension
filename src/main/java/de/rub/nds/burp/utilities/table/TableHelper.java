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

import de.rub.nds.burp.utilities.table.TableEntry;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

/**
 *
 * @author Tim Guenther
 */
public class TableHelper extends AbstractTableModel{
    
    private ArrayList<TableEntry> list;
    private String[] colName = {"#","No.","SSO Protocol","Host","Method","URL","Token","Time","Length","Comment"};

    public TableHelper(ArrayList<TableEntry> list) {
        this.list = list;
    }

    public ArrayList<TableEntry> getTableList(){
        return list;
    }
    public void addRow(TableEntry entry){
        int row = list.size();
        list.add(entry);
        fireTableRowsInserted(row,row);
    }
    
    @Override
    public int getRowCount()
    {
        return list.size();
    }

    @Override
    public int getColumnCount()
    {
        return 10;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        try {
            return colName[columnIndex];
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        TableEntry entry = list.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return entry.getCounter();
            case 1:
                return entry.getNumber();
            case 2:
                return entry.getProtocol();
            case 3:
                return entry.getHost();
            case 4:
                return entry.getMethod();
            case 5:
                return entry.getUrl();
            case 6:
                return entry.getToken() ;   
            case 7:
                return entry.getTime();
            case 8:
                return entry.getLength();
            case 9:
                return entry.getComment();
            default:
                return "";
        }
    }
}
