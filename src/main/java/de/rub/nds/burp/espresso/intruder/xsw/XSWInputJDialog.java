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
package de.rub.nds.burp.espresso.intruder.xsw;

import de.rub.nds.burp.utilities.XMLHelper;
import de.rub.nds.burp.utilities.table.ssoHistory.TableMouseListener;
import de.rub.nds.burp.utilities.table.xsw.TableEntry;
import de.rub.nds.burp.utilities.table.xsw.TableModel;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableRowSorter;
import org.w3c.dom.Document;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.option.Payload;

/**
 * @author Nurullah Erinola
 */
public class XSWInputJDialog extends javax.swing.JDialog {

    private String message;
    private Document doc;
    private HashMap<String, String> valuePairs;
    private TableModel tableModel;
    private JTable table;
    private List<Payload> payloadList;
    
    /**
     * Creates new form XSWInputJDialog
     * @param message Message to be show
     * @param payloadList Signature elements of the message
     */
    public XSWInputJDialog(String message, List<Payload> payloadList, boolean isDeflate, boolean isBase64, boolean isURL) {
        super(new JFrame(), true);
        initComponents();
        jLabelNode.setText("");
        // Init variables
        this.message = message;
        this.payloadList = payloadList;
        doc = XMLHelper.stringToDom(message);
        valuePairs = new HashMap<>();
        // Init table and editor
        initTable();
        initEditor();
        initSchemaComboBox();
        initEncoding(isDeflate, isBase64, isURL);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButtonOk = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jTextFieldCurrentValue = new javax.swing.JTextField();
        jTextFieldNewValue = new javax.swing.JTextField();
        jSeparator1 = new javax.swing.JSeparator();
        jButtonAdd = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jScrollPaneTable = new javax.swing.JScrollPane();
        jCheckBoxWrapLines = new javax.swing.JCheckBox();
        rTextScrollPane = new org.fife.ui.rtextarea.RTextScrollPane();
        rSyntaxTextArea = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel5 = new javax.swing.JLabel();
        jCheckBoxEnflate = new javax.swing.JCheckBox();
        jCheckBoxBase64 = new javax.swing.JCheckBox();
        jCheckBoxUrl = new javax.swing.JCheckBox();
        jSeparator3 = new javax.swing.JSeparator();
        jLabelNode = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jComboBoxSchema = new javax.swing.JComboBox<>();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jButtonOk.setText("Start attack");
        jButtonOk.setToolTipText("Minimum one textnode pair necessary to start attack.");
        jButtonOk.setEnabled(false);
        jButtonOk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonOkActionPerformed(evt);
            }
        });

        jLabel1.setText("Message:");

        jLabel2.setText("Current value:");

        jLabel3.setText("New value:");

        jButtonAdd.setText("Add");
        jButtonAdd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonAddActionPerformed(evt);
            }
        });

        jLabel4.setText("Textnodes to be replaced:");

        jCheckBoxWrapLines.setText("Enable Softwraps");
        jCheckBoxWrapLines.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxWrapLinesActionPerformed(evt);
            }
        });

        rTextScrollPane.setAutoscrolls(true);
        rTextScrollPane.setLineNumbersEnabled(true);

        rSyntaxTextArea.setEditable(false);
        rSyntaxTextArea.setColumns(20);
        rSyntaxTextArea.setRows(5);
        rSyntaxTextArea.setCodeFoldingEnabled(true);
        rSyntaxTextArea.setSyntaxEditingStyle("text/xml");
        rTextScrollPane.setViewportView(rSyntaxTextArea);

        jLabel5.setText("Encoding:");

        jCheckBoxEnflate.setText("Deflate");

        jCheckBoxBase64.setText("Base64");

        jCheckBoxUrl.setText("URL");

        jLabelNode.setForeground(new java.awt.Color(255, 0, 0));
        jLabelNode.setText("Error");

        jLabel6.setText("Modifications Table:");

        jLabel7.setText("Schema Analyzer:");

        jComboBoxSchema.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(rTextScrollPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jSeparator1)
                    .addComponent(jScrollPaneTable)
                    .addComponent(jButtonAdd, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jSeparator2, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jButtonOk, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jSeparator3)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextFieldCurrentValue, javax.swing.GroupLayout.DEFAULT_SIZE, 209, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextFieldNewValue, javax.swing.GroupLayout.DEFAULT_SIZE, 208, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel4)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabelNode))
                            .addComponent(jLabel6)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel7)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jComboBoxSchema, javax.swing.GroupLayout.PREFERRED_SIZE, 213, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel5)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jCheckBoxEnflate)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jCheckBoxBase64)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jCheckBoxUrl)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jCheckBoxWrapLines)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jCheckBoxWrapLines))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rTextScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 288, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(jLabelNode))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextFieldCurrentValue, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3)
                    .addComponent(jTextFieldNewValue, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonAdd)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPaneTable, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(jComboBoxSchema, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(2, 2, 2)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(jCheckBoxEnflate)
                    .addComponent(jCheckBoxBase64)
                    .addComponent(jCheckBoxUrl))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonOk)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButtonAddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonAddActionPerformed
        ArrayList<String> xPaths = new ArrayList<>();
        // Search only in signed elements
        for (int i = 0; i < payloadList.size(); i++) {
            Document payload = XMLHelper.stringToDom(payloadList.get(i).getValue());
            xPaths.addAll(XMLHelper.findNodeByValue(payload, jTextFieldCurrentValue.getText()));
        }
        if(xPaths.isEmpty()) {
            jLabelNode.setText("'" + jTextFieldCurrentValue.getText() + "'" + " not found in the signed element!");
            return;
        }
        for (int i = 0; i < xPaths.size(); i++) {
            String selection = xPaths.get(i);
            // Add pair
            if (!selection.equals("") && !valuePairs.containsKey(selection)) {
                jLabelNode.setText("");
                valuePairs.put(selection, jTextFieldNewValue.getText());
                tableModel.addRow(new TableEntry(selection, jTextFieldCurrentValue.getText(), jTextFieldNewValue.getText()));
            } else {
                jLabelNode.setText("New value for '" + jTextFieldCurrentValue.getText() + "' already added. Delete existing entry to replace it!");
            } 
        }
    }//GEN-LAST:event_jButtonAddActionPerformed

    private void jButtonOkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonOkActionPerformed
        this.dispose();
    }//GEN-LAST:event_jButtonOkActionPerformed

    private void jCheckBoxWrapLinesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxWrapLinesActionPerformed
        if (jCheckBoxWrapLines.isSelected()) {
            rSyntaxTextArea.setLineWrap(true);
        } else {
            rSyntaxTextArea.setLineWrap(false);
        }
    }//GEN-LAST:event_jCheckBoxWrapLinesActionPerformed

    private void initTable() {
        tableModel = new TableModel();
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jScrollPaneTable.setViewportView(table);
        //Enable sorting
        TableRowSorter<TableModel> sorter = new TableRowSorter<>();
        table.setRowSorter(sorter);
        sorter.setModel(tableModel);
        // Set popup menu
        JPopupMenu menu = new JPopupMenu();
        JMenuItem item = new JMenuItem("Remove current row");
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                if (table.getSelectedRow() != -1) {
                    valuePairs.remove((String) tableModel.getValueAt(table.getSelectedRow(), 0));
                    tableModel.remove(table.getSelectedRow());
                }
            }
        });
        menu.add(item);
        item = new JMenuItem("Delete all rows");
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                valuePairs.clear();
                tableModel.clearAll();
            }
        });
        menu.add(item);
        table.setComponentPopupMenu(menu);
        // Set event listener 
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent me) {
                super.mouseClicked(me);
                // selects the row at which point the mouse is clicked
                Point point = me.getPoint();
                int currentRow = table.rowAtPoint(point);
                table.setRowSelectionInterval(currentRow, currentRow);         
            }
            
        });
        // Set event listener 
        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent ke) {
                super.keyPressed(ke);
                if(ke.getKeyCode() == KeyEvent.VK_DELETE) {
                    if (table.getSelectedRow() != -1) {
                        valuePairs.remove((String) tableModel.getValueAt(table.getSelectedRow(), 0));
                        tableModel.remove(table.getSelectedRow());
                    }
                }
            }
            
        });
        // Set event listener
        tableModel.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                if(tableModel.getRowCount() > 0) {
                    jButtonOk.setEnabled(true);
                } else {
                    jButtonOk.setEnabled(false);
                }
            }
        });
    }
    
    private void initSchemaComboBox() {
        ArrayList<String> schemas = new ArrayList<>();
        schemas.add(SchemaAnalyzerFactory.ALL);
        schemas.add(SchemaAnalyzerFactory.NULL);
        schemas.add(SchemaAnalyzerFactory.EMPTY);
        schemas.add(SchemaAnalyzerFactory.MINIMAL);
        schemas.add(SchemaAnalyzerFactory.SAML);
        schemas.add(SchemaAnalyzerFactory.SAML11);
        schemas.add(SchemaAnalyzerFactory.SAML20);
        schemas.add(SchemaAnalyzerFactory.WEBSERVICE);
        jComboBoxSchema.setModel(new DefaultComboBoxModel(schemas.toArray()));
    }
    
    private void initEditor() {
        rSyntaxTextArea.setText(XMLHelper.format(message, 2));
        rSyntaxTextArea.setLineWrap(false);
        rTextScrollPane.setLineNumbersEnabled(true);
    }
    
    
    private void initEncoding(boolean isDeflate, boolean isBase64, boolean isURL) {
        jCheckBoxEnflate.setSelected(isDeflate);
        jCheckBoxBase64.setSelected(isBase64);
        jCheckBoxUrl.setSelected(isURL);
    }
    
    public String getSchema() {
        return (String) jComboBoxSchema.getSelectedItem();
    }
    
    public HashMap<String, String> getValuePairs() {
        return valuePairs;
    }
    
    public boolean getEnflateChoice() {
        return jCheckBoxEnflate.isSelected();
    }
    
    public boolean getBase64Choice() {
        return jCheckBoxBase64.isSelected();
    }
    
    public boolean getUrlChoice() {
        return jCheckBoxUrl.isSelected();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButtonAdd;
    private javax.swing.JButton jButtonOk;
    private javax.swing.JCheckBox jCheckBoxBase64;
    private javax.swing.JCheckBox jCheckBoxEnflate;
    private javax.swing.JCheckBox jCheckBoxUrl;
    private javax.swing.JCheckBox jCheckBoxWrapLines;
    private javax.swing.JComboBox<String> jComboBoxSchema;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabelNode;
    private javax.swing.JScrollPane jScrollPaneTable;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JTextField jTextFieldCurrentValue;
    private javax.swing.JTextField jTextFieldNewValue;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea rSyntaxTextArea;
    private org.fife.ui.rtextarea.RTextScrollPane rTextScrollPane;
    // End of variables declaration//GEN-END:variables
}
