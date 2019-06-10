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
package de.rub.nds.burp.espresso.gui.attacker.saml;

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
 * The Attacker for SAML messages.
 * @author Tim Guenther
 * @version 1.0
 */
public class UISAMLAttacker extends JPanel implements ItemListener{

    // The attack options.
    private final String NO_ATTACK = "No Attack";
    private final String SIGNATURE_WRAPPING = "Signature Wrapping";
    private final String SIGNATURE_EXCLUSION = "Signature Exclusion";
    private final String SIGNATURE_FAKING = "Signature Faking";
    private final String DTD = "DTD";
    private final String ENCRYPTION = "Encryption";

    private JComboBox attackComboBox;
    private JLabel descriptionLabel;
    private JPanel settingsContainer;
    
    private UISigFakeAttack uiSigFakeAttack = null;
    private UISigExcAttack uiSigExcAttack = null;
    private UIDTDAttack uiDTDAttack = null;
    private UIEncryptionAttack uiEncryptionAttack = null;
    private UISigWrapAttack uiSigWrapAttack = null;
    
    /**
     * Create a new Attacker.
     */
    public UISAMLAttacker(){
        initComponents();
    }
    
    /**
     * Show the UI for the specific attacks.
     * Called if the selection JComboBox changes.
     * @param ie The selected attack.
     */
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
        String[] attackArray = {NO_ATTACK, SIGNATURE_EXCLUSION, SIGNATURE_FAKING, SIGNATURE_WRAPPING, DTD, ENCRYPTION};
        attackComboBox.setModel(new DefaultComboBoxModel(attackArray));
        attackComboBox.addItemListener(this);

        settingsContainer = new JPanel(new CardLayout());
        settingsContainer.add(new JPanel(), NO_ATTACK);
        uiSigExcAttack = new UISigExcAttack();
        settingsContainer.add(uiSigExcAttack, SIGNATURE_EXCLUSION);
        uiSigFakeAttack = new UISigFakeAttack();
        settingsContainer.add(uiSigFakeAttack, SIGNATURE_FAKING);
        uiSigWrapAttack = new UISigWrapAttack();
	settingsContainer.add(uiSigWrapAttack, SIGNATURE_WRAPPING);
        uiDTDAttack = new UIDTDAttack();
	settingsContainer.add(uiDTDAttack, DTD);
        uiEncryptionAttack = new UIEncryptionAttack();
        settingsContainer.add(uiEncryptionAttack, ENCRYPTION);
              
        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(attackComboBox, 10, 100, Short.MAX_VALUE)
                    .addComponent(descriptionLabel, 10, 376, Short.MAX_VALUE)
                    .addComponent(settingsContainer, 10, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(descriptionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(attackComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(10, 10, 10)
                .addComponent(settingsContainer, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
}
    
    /**
     * Set enable or disable this component.
     * @param enabled True to enable, false to disable the component.
     */
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
    
    /**
     * Set the listener for the editor.
     * @param listeners {@link de.rub.nds.burp.utilities.listeners.CodeListenerController}
     */
    public void setListeners(CodeListenerController listeners){
        uiSigExcAttack.setListener(listeners);
        uiSigFakeAttack.setListener(listeners);
        uiSigWrapAttack.setListeners(listeners);
        uiDTDAttack.setListener(listeners);
        uiEncryptionAttack.setListener(listeners);
    }
    
    /**
     * Set the listener for the editor.
     * @param listeners {@link de.rub.nds.burp.utilities.listeners.CodeListenerController}
     */
    public void setListenersSignature(CodeListenerController listeners){
        uiSigExcAttack.setListener(listeners);
    }
}
