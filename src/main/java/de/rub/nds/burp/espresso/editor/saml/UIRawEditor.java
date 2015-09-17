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
import de.rub.nds.burp.utilities.Logging;
import de.rub.nds.burp.utilities.listeners.AbstractCodeEvent;
import de.rub.nds.burp.utilities.listeners.ICodeListener;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import java.awt.Component;

/**
 *
 * @author Tim Guenther
 */
public class UIRawEditor implements ITextEditor, ICodeListener{
    
    private ITextEditor burpEditor = null;
    private CodeListenerController listeners = null;
    
    public UIRawEditor(IBurpExtenderCallbacks callbacks, boolean editable){
        this.burpEditor = callbacks.createTextEditor();
        burpEditor.setEditable(editable);
    }

    @Override
    public Component getComponent() {
        return burpEditor.getComponent();
    }

    @Override
    public void setEditable(boolean editable) {
        burpEditor.setEditable(editable);
    }

    @Override
    public void setText(byte[] text) {
        burpEditor.setText(text);
    }

    @Override
    public byte[] getText() {
        return burpEditor.getText();
    }

    @Override
    public boolean isTextModified() {
        return burpEditor.isTextModified();
    }

    @Override
    public byte[] getSelectedText() {
        return burpEditor.getSelectedText();
    }

    @Override
    public int[] getSelectionBounds() {
        return burpEditor.getSelectionBounds();
    }

    @Override
    public void setSearchExpression(String expression) {
       burpEditor.setSearchExpression(expression);
    }

    @Override
    public void setCode(AbstractCodeEvent evt) {
        burpEditor.setText(evt.getCode().getBytes());
    }
    
    public void setEnabled(boolean enabled){
        if(enabled){
           burpEditor.setText(getText());
        } else {
           burpEditor.setText("".getBytes());
        }
    }

    @Override
    public void setListener(CodeListenerController listeners) {
        this.listeners = listeners;
        this.listeners.addCodeListener(this);
    }
}
