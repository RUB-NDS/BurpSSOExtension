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
import burp.IExtensionHelpers;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

/**
 *
 * @author Tim Guenther
 */
public class UISourceViewer extends JPanel{
    
    private IBurpExtenderCallbacks callbacks;
    private String sourceCode = "<demo></demo>";
    private String codeStyle = SyntaxConstants.SYNTAX_STYLE_XML;
    private RSyntaxTextArea textArea;

    public UISourceViewer(IBurpExtenderCallbacks callbacks) {
        super(new BorderLayout());
        this.callbacks = callbacks;
        this.codeStyle = codeStyle;
        
        //set source code
        IExtensionHelpers helpers = callbacks.getHelpers();
        
        initComponent();
    }

    public UISourceViewer(String sourceCode, String codeStyle) {
        super(new BorderLayout());
        this.sourceCode = sourceCode;
        this.codeStyle = codeStyle;
        initComponent();
    }
    
    public UISourceViewer(){
        super(new BorderLayout());
        initComponent();
    }
    
    private void initComponent(){
        textArea = new RSyntaxTextArea(20, 60);
        textArea.setSyntaxEditingStyle(codeStyle);
        textArea.setText(sourceCode);
        textArea.setCodeFoldingEnabled(true);
        RTextScrollPane sp = new RTextScrollPane(textArea);
        this.add(sp);
    }
    
    public void setText(String sourceCode, String codeStyle){
        this.sourceCode = sourceCode;
        this.codeStyle = codeStyle;
        textArea.setSyntaxEditingStyle(codeStyle);
        textArea.setText(sourceCode);
        this.updateUI();
    }
      
    
}
