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
package de.rub.nds.burp.espresso.editor.saml;

import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
import de.rub.nds.burp.utilities.listeners.AbstractCodeEvent;
import de.rub.nds.burp.utilities.listeners.ICodeListener;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import java.awt.Component;

/**
 * Show the text without syntax highlight.
 * The Editor is based on Burps ITextEditor.
 * @author Tim Guenther
 * @version 1.0
 */
public class UIRawEditor implements ITextEditor, ICodeListener{
    
    private ITextEditor burpEditor = null;
    private CodeListenerController listeners = null;
    
    /**
     * Create a new {@link burp.ITextEditor} to implement a new Burp like text area.
     * This includes the bottom search and regex input fields.
     * @param callbacks {@link burp.IBurpExtenderCallbacks}
     * @param editable True if message is editable, false otherwise.
     */
    public UIRawEditor(IBurpExtenderCallbacks callbacks, boolean editable){
        this.burpEditor = callbacks.createTextEditor();
        burpEditor.setEditable(editable);
    }

    /**
     * Get the Component.
     * @return The Burp like text area as a component.
     */
    @Override
    public Component getComponent() {
        return burpEditor.getComponent();
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
}
