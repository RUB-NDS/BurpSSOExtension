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
package de.rub.nds.burp.espresso.editor.saml;

import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
import de.rub.nds.burp.utilities.listeners.AbstractCodeEvent;
import de.rub.nds.burp.utilities.listeners.ICodeListener;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import java.awt.Component;
import java.awt.GridLayout;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
        
/**
 * Show the text without syntax highlight.
 * The Editor is based on Burps ITextEditor.
 * @author Tim Guenther
 * @version 1.0
 */
public class UIRawEditor extends JPanel implements ITextEditor, ICodeListener{
    
    private ITextEditor burpEditor = null;
    private CodeListenerController listeners = null;
    private JScrollPane rawEditor;
    private JCheckBox base64CheckBox;
    private JCheckBox urlCheckBox;
    private JCheckBox deflateCheckBox;
    private JCheckBox changeHttpMethodCheckbox;
    private JCheckBox changeAllParameters;
    
    /**
     * Create a new {@link burp.ITextEditor} to implement a new Burp like text area.
     * This includes the bottom search and regex input fields.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     * @param editable True if message is editable, false otherwise.
     */
    public UIRawEditor(IBurpExtenderCallbacks callbacks, boolean editable){
        this.burpEditor = callbacks.createTextEditor();
        burpEditor.setEditable(editable);
        initComponents();
    }
    
    private void initComponents() {

        rawEditor = new JScrollPane();
        rawEditor.setViewportView(burpEditor.getComponent());
        
        base64CheckBox = new JCheckBox("Base64");
        urlCheckBox = new JCheckBox("URL Enc");
        deflateCheckBox = new JCheckBox("Deflate");
        changeHttpMethodCheckbox = new JCheckBox("Change HTTP method");
        changeHttpMethodCheckbox.setToolTipText("Change GET <-> POST with SAML parameter.");
        changeHttpMethodCheckbox.setEnabled(true);
        changeHttpMethodCheckbox.addChangeListener(new ChangeListener() {
               @Override
                public void stateChanged(ChangeEvent ce) {
                        clickedChangeHttpMethodCheckbox();
                }
            });
        changeAllParameters = new JCheckBox("Switch all parameters");
        changeAllParameters.setToolTipText("Change GET <-> POST with all paramater.");
        changeAllParameters.setEnabled(false);
                
        GroupLayout layout = new GroupLayout(this);
        layout.setVerticalGroup(layout.createParallelGroup()
            .addComponent(rawEditor)
            .addGroup(layout.createSequentialGroup()
                .addComponent(deflateCheckBox)
                .addComponent(base64CheckBox)
                .addComponent(urlCheckBox)
                .addComponent(changeHttpMethodCheckbox)
                .addComponent(changeAllParameters)));
        layout.setHorizontalGroup(layout.createSequentialGroup()
            .addComponent(rawEditor)
            .addGroup(layout.createParallelGroup()
                .addComponent(deflateCheckBox)
                .addComponent(base64CheckBox)
                .addComponent(urlCheckBox)
                .addComponent(changeHttpMethodCheckbox)
                .addComponent(changeAllParameters)));
        this.setLayout(layout);
    }

    /**
     * Enable/Disable "changeAllParameters" checkbox
     */   
    private void clickedChangeHttpMethodCheckbox() {
        if(changeHttpMethodCheckbox.isSelected()) {
            changeAllParameters.setEnabled(true);
        } else {
            changeAllParameters.setEnabled(false);
        }
    }

    /**
     * Disable checkboxes in the history.
     */   
    public void disableModifyFeatures() {
        this.removeAll();
        this.setLayout(new GridLayout(1,1));
        this.add(rawEditor);
    }

    /**
     * Get the Component.
     * @return The Burp like text area as a component.
     */
    @Override
    public Component getComponent() {
        return this;
    }

    /**
     * Set if the text area should allow modifications.
     * @param editable True, the text area is editable, false, the text 
     * area is not editable.
     */
    @Override
    public void setEditable(boolean editable) {
        burpEditor.setEditable(editable);
    }

    /**
     * Set the text of the text area.
     * @param text The text to set.
     */
    @Override
    public void setText(byte[] text) {
        burpEditor.setText(text);
    }

    /**
     * Get the text of the text area.
     * @return The text of the text area.
     */
    @Override
    public byte[] getText() {
        return burpEditor.getText();
    }

    /**
     * Check if the text is modified.
     * @return True if text is modified, false otherwise.
     */
    @Override
    public boolean isTextModified() {
        return burpEditor.isTextModified();
    }

    /**
     * Get the selected text.
     * @return The selected text
     */
    @Override
    public byte[] getSelectedText() {
        return burpEditor.getSelectedText();
    }

    /**
     * Get the start and end of the selected text.
     * @return Start and end of the selected text.
     */
    @Override
    public int[] getSelectionBounds() {
        return burpEditor.getSelectionBounds();
    }

    /**
     * Set the serach or regular expression
     * @param expression The search or regular expression.
     */
    @Override
    public void setSearchExpression(String expression) {
       burpEditor.setSearchExpression(expression);
    }
    
    /**
     * Set enable or disable this component.
     * @param enabled True to enable, false to disable the component.
     */
    public void setEnabled(boolean enabled){
        if(enabled){
           burpEditor.setText(getText());
        } else {
           burpEditor.setText("".getBytes());
        }
    }

    /**
     * Is called every time new Code is available.
     * @param evt {@link de.rub.nds.burp.utilities.listeners.AbstractCodeEvent} The new source code.
     */
    @Override
    public void setCode(AbstractCodeEvent evt) {
        burpEditor.setText(evt.getCode().getBytes());
    }

    /**
     * Set the listener for the editor.
     * @param listeners {@link de.rub.nds.burp.utilities.listeners.CodeListenerController}
     */
    @Override
    public void setListener(CodeListenerController listeners) {
        this.listeners = listeners;
        this.listeners.addCodeListener(this);
    }

    public JCheckBox getBase64CheckBox() {
        return base64CheckBox;
    }
        
    public JCheckBox getDeflateCheckBox() {
        return deflateCheckBox;
    }
    
    
    public JCheckBox getUrlCheckBox() {
        return urlCheckBox;
    }

    public JCheckBox getChangeHttpMethodCheckBox() {
        return changeHttpMethodCheckbox;
    }

    public JCheckBox getChangeAllParameters() {
        return changeAllParameters;
    }

    /**
     * Set all checkboxes false
     */
    public void clearCheckBoxes() {
        deflateCheckBox.setSelected(false);
        base64CheckBox.setSelected(false);
        urlCheckBox.setSelected(false);
        changeHttpMethodCheckbox.setSelected(false);
        changeAllParameters.setSelected(false);
    }
}
