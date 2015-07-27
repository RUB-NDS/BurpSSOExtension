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
package de.rub.guenther.tim.espresso.gui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import de.rub.guenther.tim.espresso.utilities.Table;
import de.rub.guenther.tim.espresso.utilities.TableDB;
import de.rub.guenther.tim.espresso.utilities.TableEntry;
import de.rub.guenther.tim.espresso.utilities.TableHelper;
import java.util.ArrayList;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/**
 *
 * @author Tim Guenther
 */
public class UIHistory extends JSplitPane implements IMessageEditorController{
    
    private IBurpExtenderCallbacks callbacks;
    
    private JTabbedPane historyContainer;
    private Table ssoHistoryTable;
    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IHttpRequestResponse currentlyDisplayedItem;

    public UIHistory(IBurpExtenderCallbacks callbacks) {
        super(JSplitPane.VERTICAL_SPLIT);
        this.callbacks = callbacks;
        initComponent();
    }
    
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
        
        TableDB.addTable(ssoHistoryTable);
    }
    
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
