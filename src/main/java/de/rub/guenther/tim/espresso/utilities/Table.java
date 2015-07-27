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
package de.rub.guenther.tim.espresso.utilities;

import de.rub.guenther.tim.espresso.gui.UIMain;
import de.rub.guenther.tim.espresso.gui.UIHistory;
import java.util.ArrayList;
import javax.swing.JTable;

/**
 *
 * @author Tim Guenther
 */
public class Table extends JTable
    {
        private TableHelper th;
        private ArrayList<TableEntry> list;
        private String name;
    
        public Table(TableHelper th, String name)
        {
            super(th); 
            this.th = th;
            this.list = th.getTableList();
            this.name = name;
        }
        
        public String getName(){
            return name;
        }
        
        public TableHelper getTableHelper(){
            return th;
        }
        
        public ArrayList<TableEntry> getTableList(){
            return list;
        }
        
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
    }
