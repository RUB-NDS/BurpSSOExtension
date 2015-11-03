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

import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JTable;

/**
 * A mouse listener for a JTable component.
 * Copied from http://www.codejava.net/java-se/swing/jtable-popup-menu-example
 * @author www.codejava.neet
 * @version 1.0
 */
public class TableMouseListener extends MouseAdapter{
    private JTable table;
	
    /**
     * Create a new TableMouseListener for a table. 
     * @param table The table to listen to.
     */
    public TableMouseListener(JTable table) {
            this.table = table;
    }

    /**
     * Activate if mouse is pressed.
     * @param event The event that is passed.
     */
    @Override
    public void mousePressed(MouseEvent event) {
            // selects the row at which point the mouse is clicked
            Point point = event.getPoint();
            int currentRow = table.rowAtPoint(point);
            table.setRowSelectionInterval(currentRow, currentRow);
    }
}
