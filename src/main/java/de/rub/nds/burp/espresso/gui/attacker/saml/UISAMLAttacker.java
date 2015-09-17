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
package de.rub.nds.burp.espresso.gui.attacker.saml;

import burp.ITextEditor;
import de.rub.nds.burp.utilities.listeners.CodeListenerController;
import java.awt.CardLayout;
import java.awt.Font;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 *
 * @author Tim Guenther
 */
public class UISAMLAttacker extends JPanel implements ItemListener{

    private final String NO_ATTACK = "No Attack";
    private final String SIGNATURE_WRAPPING = "Signature Wrapping";
    private final String SIGNATURE_FAKING = "Signature Faking";

    private JComboBox attackComboBox;
    private JLabel descriptionLabel;
    private JPanel settingsContainer;
    
    private UISigWrapAttack uiSigWrapAttack = null;
    private UISigFakeAttack uiSigFakeAttack = null;
    
    public UISAMLAttacker(){
        initComponents();
    }
    

    @Override
    public void itemStateChanged(ItemEvent ie) {
        CardLayout cl = (CardLayout)(settingsContainer.getLayout());
        cl.show(settingsContainer, (String) ie.getItem());
    }

    private void initComponents() {
        descriptionLabel = new JLabel();
        descriptionLabel.setFont(new Font("Dialog", 0, 12)); // NOI18N
        descriptionLabel.setText("Choose an attack for the intercepted message.");

        attackComboBox = new JComboBox();
        attackComboBox.setFont(new Font("Dialog", 0, 12));
        String[] attackArray = {NO_ATTACK, SIGNATURE_FAKING, SIGNATURE_WRAPPING};
        attackComboBox.setModel(new DefaultComboBoxModel(attackArray));
        attackComboBox.addItemListener(this);

        settingsContainer = new JPanel(new CardLayout());
        settingsContainer.add(new JPanel(), NO_ATTACK);
        uiSigFakeAttack = new UISigFakeAttack();
        settingsContainer.add(uiSigFakeAttack, SIGNATURE_FAKING);
        uiSigWrapAttack = new UISigWrapAttack();
	settingsContainer.add(uiSigWrapAttack, SIGNATURE_WRAPPING);

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(attackComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(descriptionLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 376, Short.MAX_VALUE)
                    .addComponent(settingsContainer, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(descriptionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(attackComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(settingsContainer, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }
    
    @Override
    public void setEnabled(boolean enabled){
        super.setEnabled(enabled);
        CardLayout cl;
        cl = (CardLayout)(settingsContainer.getLayout());
        if(!enabled){
            cl.show(settingsContainer, NO_ATTACK);
        } else {
            cl.show(settingsContainer, attackComboBox.getSelectedItem().toString());
        }
        attackComboBox.setEnabled(enabled);
    }
    
    public void setListeners(CodeListenerController listeners){
        uiSigFakeAttack.setListener(listeners);
        uiSigWrapAttack.setListener(listeners);
    }
}
