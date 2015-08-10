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
package de.rub.nds.burp.espresso.gui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import de.rub.nds.burp.espresso.gui.contextmenu.FollowProtocol;
import de.rub.nds.burp.utilities.table.Table;
import de.rub.nds.burp.utilities.table.TableDB;
import de.rub.nds.burp.utilities.table.TableEntry;
import de.rub.nds.burp.utilities.table.TableHelper;
import de.rub.nds.burp.utilities.table.TableMouseListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 * SSO History displays all Single Sign-On related messages.
 * @author Tim Guenther
 * @version 1.0
 */
public class UIHistory extends JSplitPane implements IMessageEditorController{
    
    private IBurpExtenderCallbacks callbacks;
    
    private JTabbedPane historyContainer;
    private Table ssoHistoryTable;
    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IHttpRequestResponse currentlyDisplayedItem;

    /**
     * Create a vertical split history window.
     * @param callbacks 
     */
    public UIHistory(IBurpExtenderCallbacks callbacks) {
        super(JSplitPane.VERTICAL_SPLIT);
        this.callbacks = callbacks;
        initComponent();
    }
    
    /**
     * Initialise all components. 
     */
    private void initComponent(){
        //top part
        historyContainer = new JTabbedPane();
        
        ssoHistoryTable = new Table(new TableHelper(new ArrayList<TableEntry>()), "Full History");
        JScrollPane scrollPane = new JScrollPane(ssoHistoryTable);
        historyContainer.addTab(ssoHistoryTable.getName(), scrollPane);
        this.setTopComponent(historyContainer);
        
        //bottom part
        JTabbedPane tab = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);
        tab.addTab("Request", requestViewer.getComponent());
        tab.addTab("Response", responseViewer.getComponent());
        
        this.setBottomComponent(tab);
        
        //context menu
        ssoHistoryTable.addMouseListener(new TableMouseListener(ssoHistoryTable));
        JPopupMenu menu = new JPopupMenu();
        JMenuItem item = new JMenuItem(FollowProtocol.CAPTION);
        item.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent ae) {
                JMenuItem menu = (JMenuItem) ae.getSource();
                if (menu == item) {
                    int row = ssoHistoryTable.getSelectedRow();
                    String id = (String) ssoHistoryTable.getValueAt(row, 6);
                    if(addNewTable(id)){
                        try {
                            //a little race condition with the new tab
                            Thread.sleep(500);
                        } catch (InterruptedException ex) {
                        }
                        new PrintWriter(callbacks.getStdout(), true).println("test");
                        ArrayList<TableEntry> list = ssoHistoryTable.getTableList();
                        for(TableEntry e : list){
                            if(e.getToken().equals(id)){
                                new PrintWriter(callbacks.getStdout(), true).println("1");
                                TableDB.getTable(id).getTableHelper().addRow(e);
                            }
                        }
                    }
		}
            }
        });
        menu.add(item);
        ssoHistoryTable.setComponentPopupMenu(menu);
        
        //Enable sorting
        TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>();
        ssoHistoryTable.setRowSorter(sorter);
        sorter.setModel(ssoHistoryTable.getModel());
                
        TableDB.addTable(ssoHistoryTable);
    }
    
    /**
     * Add a table to the history UI.
     * @param tableName Name of the table, is displayed in the new tab. 
     * @return 
     */
    public boolean addNewTable(String tableName){
        //find tables with same name
        if(TableDB.getTable(tableName) != null){
            return false;
        }
        
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {   
                Table t = new Table(new TableHelper(new ArrayList<TableEntry>()),tableName);
                JScrollPane s = new JScrollPane(t);
                
                historyContainer.addTab(t.getName(), s);
                
                TableDB.addTable(t);
            }
        });
        
        return true;
    }
    
    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }
}
