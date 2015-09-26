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
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.protocols.SSOProtocol;
import de.rub.nds.burp.utilities.table.Table;
import de.rub.nds.burp.utilities.table.TableDB;
import de.rub.nds.burp.utilities.table.TableEntry;
import de.rub.nds.burp.utilities.table.TableHelper;
import de.rub.nds.burp.utilities.table.TableMouseListener;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
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

    /**
     * The request viewer of Burp.
     */
    public static IMessageEditor requestViewer;

    /**
     * The response viewer of Burp.
     */
    public static IMessageEditor responseViewer;

    /**
     * The currently displayed http message.
     */
    public static IHttpRequestResponse currentlyDisplayedItem;

    /**
     * Number of open tabs.
     */
    public static int tab_counter = 1;

    /**
     * Create a vertical split history window.
     * @param callbacks Helper provided by the Burp Suite api.
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
        
        ssoHistoryTable = new Table(new TableHelper(new ArrayList<TableEntry>()), "Full History", "Default_ssoHistory");
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
        JPopupMenu.Separator separator = new JPopupMenu.Separator();
        JMenuItem item = new JMenuItem("Analyse SSO Protocol");
        item.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent ae) {
                int row = ssoHistoryTable.getSelectedRow();
                String protocol = (String) ssoHistoryTable.getValueAt(row, 1);
                
                TableEntry entry = (TableEntry) ssoHistoryTable.getTableEntry(row);
                SSOProtocol sso = entry.getSSOProtocol();
                
                addNewTable(protocol+" "+(tab_counter++), (new Integer(sso.getProtocolflowID())).toString(), sso);
            }
        });
        menu.add(item);
        menu.add(separator);
        separator = new JPopupMenu.Separator();
        menu.add(separator);
        item = new JMenuItem("Add Selected to Table");
        item.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent ae) {
                JOptionPane.showMessageDialog(historyContainer,
                            "This Action is not yet implemented!",
                            "Warning",
                            JOptionPane.WARNING_MESSAGE);
            }
        });
        menu.add(item);
        item = new JMenuItem("Clear History");
        item.addActionListener(new ActionListener() {

            //TODO
            @Override
            public void actionPerformed(ActionEvent ae) {
                JOptionPane.showMessageDialog(historyContainer,
                            "This Action is not yet implemented!",
                            "Warning",
                            JOptionPane.WARNING_MESSAGE);
//                for(int i = 1; i <= TableDB.size(); i++){
//                    Table t = TableDB.getTable(i);
//                    historyContainer.removeTabAt(historyContainer.indexOfTab(t.getName()));
//                    t.getTableHelper().clear();
//                }
//                TableDB.clear();
            }
        });
        menu.add(item);
        ssoHistoryTable.setComponentPopupMenu(menu);
        
        //Enable sorting
        TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>();
        ssoHistoryTable.setRowSorter(sorter);
        sorter.setModel(ssoHistoryTable.getModel());
        ssoHistoryTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
                
        TableDB.addTable(ssoHistoryTable);
    }
    
    /**
     * Add a table to the history UI.
     * @param tableName Name of the table, is displayed in the new tab. 
     * @param id The id for the requests.
     * @param sso The SSO Protocol that should be stored in the table.
     * @return False if table exists, otherwise true.
     */
    public boolean addNewTable(String tableName, String id, SSOProtocol sso){
        //find tables with same name
        if(TableDB.getTable(id) != null){
            Logging.getInstance().log(getClass(), "Can't create new table. Table already exists.", Logging.ERROR);
            return false;
        }
        
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {   
//                Table t = new Table(new TableModel(new ArrayList<TableEntry>()),tableName,id);
//                ArrayList<TableEntry> list = ssoHistoryTable.getTableList();
//                for(TableEntry e : list){
//                    if(e.getToken().equals(id)){
//                        t.getTableHelper().addRow(e);
//                    }
//                }
                Table t = sso.toTable(tableName, id);
                
                
                JScrollPane s = new JScrollPane(t);
                historyContainer.addTab(t.getName(), s);
                
                //Setup close button for tab
                //thanks to: http://stackoverflow.com/questions/11553112/how-to-add-close-button-to-a-jtabbedpane-tab
                String title = t.getName();
                int index = historyContainer.indexOfTab(title);
                JPanel pnlTab = new JPanel(new GridBagLayout());
                pnlTab.setOpaque(false);
                JLabel lblTitle = new JLabel(title+"  ");
                JLabel btnClose = new JLabel("x");

                GridBagConstraints gbc = new GridBagConstraints();
                gbc.gridx = 0;
                gbc.gridy = 0;
                gbc.weightx = 1;

                pnlTab.add(lblTitle, gbc);

                gbc.gridx++;
                gbc.weightx = 0;
                pnlTab.add(btnClose, gbc);

                historyContainer.setTabComponentAt(index, pnlTab);

                btnClose.setToolTipText("Click to close tab.");
                btnClose.setOpaque(false);
                btnClose.setBackground(Color.lightGray);
                        
                btnClose.addMouseListener(new MouseListener() {

                    @Override
                    public void mouseClicked(MouseEvent me) {
                        int index = historyContainer.indexOfTab(title);
                        if (index >= 0) {

                            historyContainer.removeTabAt(index);
                            TableDB.removeTable(t);
                            Logging.getInstance().log(getClass(), "Closed Table {"+t.getName()+"}.", Logging.DEBUG);
                            
                        }
                    }

                    @Override
                    public void mousePressed(MouseEvent me) {
                        int index = historyContainer.indexOfTab(title);
                        if (index >= 0) {

                            historyContainer.removeTabAt(index);
                            TableDB.removeTable(t);
                        }
                    }

                    @Override
                    public void mouseReleased(MouseEvent me) {
                        int index = historyContainer.indexOfTab(title);
                        if (index >= 0) {

                            historyContainer.removeTabAt(index);
                            TableDB.removeTable(t);
                        }
                    }

                    @Override
                    public void mouseEntered(MouseEvent me) {
                        btnClose.setBackground(Color.black);
                    }

                    @Override
                    public void mouseExited(MouseEvent me) {
                        btnClose.setBackground(Color.lightGray);
                    }
                    
                });
//                        addActionListener(new ActionListener() {
//                    
//                    @Override
//                    public void actionPerformed(ActionEvent evt) {
//                        int index = historyContainer.indexOfTab(title);
//                        if (index >= 0) {
//
//                            historyContainer.removeTabAt(index);
//                            TableDB.removeTable(t);
//                        }
//                    }
//                }
//);
                
                TableDB.addTable(t);
                Logging.getInstance().log(getClass(), "Add the new Table {"+sso.getProtocol()+" "+tab_counter+"} as a tab.", Logging.DEBUG);
            }
        });
        
        return true;
    }
    
    /**
     * Get the {@link burp.IHttpService} of the displayed message
     * @return The {@link burp.IHttpService} of the displayed message.
     */
    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    /**
     * Get the request of the current message.
     * @return The request.
     */
    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    /**
     * Get the response of the current message.
     * @return The response.
     */
    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }
}
