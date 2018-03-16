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
package de.rub.nds.burp.espresso.gui;

import burp.IBurpExtenderCallbacks;
import de.rub.nds.burp.utilities.Logging;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * The options to control the extension.
 * @author Tim Guenther
 * @version 1.0
 */
public class UIOptions extends JPanel {
    private IBurpExtenderCallbacks callbacks;

    private JFileChooser fc;
    
    private File schema, cert, privkey, pubkey;
    private File scriptOut, scriptIn;
    private File extLib, config;
    
    private static boolean configInitialized;
    private static boolean samlActive=true;
    private static boolean openIDActive=true;
    private static boolean openIDConnectActive=true;
    private static boolean browserIDActive=true;
    private static boolean oAuthActive=true;
    private static boolean facebookConnectActive=true;
    private static boolean msAccountActive=true;
    private static boolean highlightBool=true;
    
    private static int LoggingLevel = 2; //0 = Info, 1 = Debug, 2 = Verbose
    
    

    /**
     * Creates new form UIOptions
     */
    public UIOptions(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();
        hideAllUnsedComponents();
        
        configInitialized = Boolean.valueOf(callbacks.loadExtensionSetting("configInitialized"));
        if (configInitialized) {
            loadConfig();
        } else {
            // first time extension is loaded, use default values
            saveConfig();
            callbacks.saveExtensionSetting("configInitialized", "true");
        }
    }
    
    /**
     * Load the configuration file and apply the configs to the UI. 
     * @param path The absolute path to the configuration file.
     */
    private void importConfig(String path){
        File file = new File(path);
        if(!file.exists()){
            JOptionPane.showMessageDialog(this,
                        "The config file does not exist!",
                        "File does not exist",
                        JOptionPane.ERROR_MESSAGE);
            return;
        }
        if(!file.isDirectory() && file.canRead()){
            JSONParser parser = new JSONParser();
            try {
                FileReader fr = new FileReader(file);
                JSONObject json_conf = (JSONObject) parser.parse(fr);
                
                openIDActive = (boolean) json_conf.get("OpenIDActive");
                openID1.setSelected(openIDActive);
                openIDConnectActive = (boolean) json_conf.get("OpenIDConnectActive");
                openIDConnect1.setSelected(openIDConnectActive);
                oAuthActive = (boolean) json_conf.get("OAuthActive");
                oAuth.setSelected(oAuthActive);
                facebookConnectActive = (boolean) json_conf.get("FacebookConnectActive");
                facebookConnect.setSelected(facebookConnectActive);
                browserIDActive = (boolean) json_conf.get("BrowserIDActive");
                browserID1.setSelected(browserIDActive);
                samlActive = (boolean) json_conf.get("SAMLActive");
                saml1.setSelected(samlActive);
                msAccountActive = (boolean) json_conf.get("MicrosoftAccountActive");
                msAccount.setSelected(msAccountActive);
                
                boolean asp = (boolean) json_conf.get("SSOActive");
                activeSSOProtocols.setSelected(asp);
                if(!asp){
                    oAuth.setEnabled(false);
                    facebookConnect.setEnabled(false);
                    saml1.setEnabled(false);
                    openID1.setEnabled(false);
                    openIDConnect1.setEnabled(false);
                    browserID1.setEnabled(false);
                    msAccount.setEnabled(false);
                }
                
                highlightBool = (boolean) json_conf.get("HighlightActive");
                highlightSSO.setSelected(highlightBool);
                
                String str = (String) json_conf.get("Schema");
                schemaText1.setText(str);
                str = (String) json_conf.get("Certificate");
                certText1.setText(str);
                str = (String) json_conf.get("Private Key");
                privKeyText1.setText(str);
                str = (String) json_conf.get("Public Key");
                pubKeyText1.setText(str);
                
                str = (String) json_conf.get("Input Script");
                scriptInText1.setText(str);
                str = (String) json_conf.get("Output Script");
                scriptOutText1.setText(str);
                
                str = (String) json_conf.get("Libraries");
                libText1.setText(str);
                
//                str = (String) json_conf.get("Config");
                
                LoggingLevel = ((Long) json_conf.get("LogLvl")).intValue();
                logginglvlComboBox.setSelectedIndex(LoggingLevel);
                
//                JOptionPane.showMessageDialog(this,
//                            "The config from "+str+" is imported.",
//                            "Import successfull",
//                            JOptionPane.INFORMATION_MESSAGE);
//                
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                            "Can not read the config file!\n\nError:\n"+ex.toString(),
                            "Can not read config file",
                            JOptionPane.ERROR_MESSAGE);
                Logging.getInstance().log(getClass(), ex);
            } catch (ParseException ex){
                JOptionPane.showMessageDialog(this,
                            "The content can not be parsed!\n\nError:\n"+ex.toString(),
                            "JSON Parsing Error",
                            JOptionPane.ERROR_MESSAGE);
                Logging.getInstance().log(getClass(), ex);
            } catch (Exception ex){
                Logging.getInstance().log(getClass(), ex);
            }
            
        } else {
            JOptionPane.showMessageDialog(this,
                            "The file:\n"+path+"\n is not readable or directory.",
                            "File not Found!",
                            JOptionPane.ERROR_MESSAGE);
            Logging.getInstance().log(getClass(), "The file:\n"+path+"\n is not readable or directory.", Logging.ERROR);
        }
        saveConfig();
        Logging.getInstance().log(getClass(), "The config from "+path+" is now loaded.", Logging.INFO);
    }
    
    /**
     * Save all configurations in the UI to the system.
     * @param path The path to the place where the configuration file should be stored.
     */
    private void exportConfig(String path){
        File file = new File(path);
        if(!file.exists()){
            try {
                file.createNewFile();
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                            "Can not create the config file.",
                            "Can not create file.",
                            JOptionPane.ERROR_MESSAGE);
                Logging.getInstance().log(getClass(), ex);
            } catch(Exception ex) {
                Logging.getInstance().log(getClass(), ex);
            }
        }
        if(!file.isDirectory() && file.canWrite() && file.canRead()){
            
            JSONObject config_obj = new JSONObject();
            config_obj.put("SSOActive", activeSSOProtocols.isSelected());
            config_obj.put("OpenIDActive", openID1.isSelected());
            config_obj.put("OpenIDConnectActive", openIDConnect1.isSelected());
            config_obj.put("OAuthActive", oAuth.isSelected());
            config_obj.put("FacebookConnectActive", facebookConnect.isSelected());
            config_obj.put("BrowserIDActive", browserID1.isSelected());
            config_obj.put("SAMLActive", saml1.isSelected());
            config_obj.put("MicrosoftAccountActive", msAccount.isSelected());
            
            config_obj.put("HighlightActive", highlightBool);
            
            config_obj.put("Schema", schemaText1.getText());
            config_obj.put("Certificate", certText1.getText());
            config_obj.put("Private Key", privKeyText1.getText());
            config_obj.put("Public Key", pubKeyText1.getText());
            
            config_obj.put("Input Script", scriptInText1.getText());
            config_obj.put("Output Script", scriptOutText1.getText());
            
            config_obj.put("Libraries", libText1.getText());
            
//            config_obj.put("Config", path);
            
            config_obj.put("LogLvl", LoggingLevel);
            
            try {
                FileWriter fw = new FileWriter(file);
                try{
                    fw.write(config_obj.toJSONString());
//                    JOptionPane.showMessageDialog(this,
//                                "The config is now saved.",
//                                "Saved successfully.",
//                                JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this,
                                "The config file can not be written!\n\nError:\n"+ex.toString(),
                                "Can not write in config file",
                                JOptionPane.ERROR_MESSAGE);
                    Logging.getInstance().log(getClass(), ex);
                } finally {
                    fw.flush();
                    fw.close();
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                            "Can not open the config file!\n\nError:\n"+ex.toString(),
                            "Can not open config file",
                            JOptionPane.ERROR_MESSAGE);
                Logging.getInstance().log(getClass(), ex);
            } catch(Exception ex) {
                Logging.getInstance().log(getClass(), ex);
            }
            
        } else {
            JOptionPane.showMessageDialog(this,
                            "The file:\n"+path+"\n is not readable/writable.",
                            "File not Found!",
                            JOptionPane.ERROR_MESSAGE);
            Logging.getInstance().log(getClass(), "The file:"+path+" is not readable/writable.", Logging.ERROR);
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane = new javax.swing.JScrollPane();
        scrollPanel = new javax.swing.JPanel();
        ssoSeparator1 = new javax.swing.JSeparator();
        ssoLabel1 = new javax.swing.JLabel();
        openID1 = new javax.swing.JCheckBox();
        openIDConnect1 = new javax.swing.JCheckBox();
        oAuth = new javax.swing.JCheckBox();
        facebookConnect = new javax.swing.JCheckBox();
        browserID1 = new javax.swing.JCheckBox();
        saml1 = new javax.swing.JCheckBox();
        highlightSSO = new javax.swing.JCheckBox();
        cryptoSeparator1 = new javax.swing.JSeparator();
        cryptoLabel1 = new javax.swing.JLabel();
        schemaLabel1 = new javax.swing.JLabel();
        schemaText1 = new javax.swing.JTextField();
        schemaOpen1 = new javax.swing.JButton();
        certLabel1 = new javax.swing.JLabel();
        certText1 = new javax.swing.JTextField();
        certOpen1 = new javax.swing.JButton();
        privKeyLabel1 = new javax.swing.JLabel();
        privKeyText1 = new javax.swing.JTextField();
        privKeyOpen1 = new javax.swing.JButton();
        pubKeyLabel1 = new javax.swing.JLabel();
        pubKeyText1 = new javax.swing.JTextField();
        pubKeyOpen1 = new javax.swing.JButton();
        scriptingSeperator1 = new javax.swing.JSeparator();
        scriptingLabel1 = new javax.swing.JLabel();
        scriptingDescription1 = new javax.swing.JLabel();
        scriptInLabel1 = new javax.swing.JLabel();
        scriptInText1 = new javax.swing.JTextField();
        scriptInOpen1 = new javax.swing.JButton();
        scriptOutLabel1 = new javax.swing.JLabel();
        scriptOutText1 = new javax.swing.JTextField();
        scriptOutOpen1 = new javax.swing.JButton();
        extLibSeparator1 = new javax.swing.JSeparator();
        extLibLabel1 = new javax.swing.JLabel();
        libLabel1 = new javax.swing.JLabel();
        libText1 = new javax.swing.JTextField();
        libOpen1 = new javax.swing.JButton();
        saveConfSeparator1 = new javax.swing.JSeparator();
        saveConfLabel1 = new javax.swing.JLabel();
        configLabel1 = new javax.swing.JLabel();
        configText1 = new javax.swing.JLabel();
        configSave1 = new javax.swing.JButton();
        configImport = new javax.swing.JButton();
        activeSSOProtocols = new javax.swing.JCheckBox();
        msAccount = new javax.swing.JCheckBox();
        configApply = new javax.swing.JButton();
        logginglvlComboBox = new javax.swing.JComboBox();
        logginglvlLabel = new javax.swing.JLabel();
        hintLabel = new javax.swing.JLabel();
        hintTextLabel = new javax.swing.JLabel();
        loggingLabel = new javax.swing.JLabel();
        loggingSeparator = new javax.swing.JSeparator();

        ssoLabel1.setText("Active SSO Protocols");

        openID1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        openID1.setSelected(true);
        openID1.setText("OpenID");
        openID1.setToolTipText("Disable/Enable OpenID");
        openID1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openID1ActionPerformed(evt);
            }
        });

        openIDConnect1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        openIDConnect1.setSelected(true);
        openIDConnect1.setText("OpenID Connect");
        openIDConnect1.setToolTipText("Disable/Enable OpenID Connect");

        oAuth.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        oAuth.setSelected(true);
        oAuth.setText("OAuth");
        oAuth.setToolTipText("Disable/Enable OAuth v1.0");
        oAuth.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                oAuthActionPerformed(evt);
            }
        });

        facebookConnect.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        facebookConnect.setSelected(true);
        facebookConnect.setText("FacebookConnect");
        facebookConnect.setToolTipText("Disable/Enable OAuth v2.0");
        facebookConnect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                facebookConnectActionPerformed(evt);
            }
        });

        browserID1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        browserID1.setSelected(true);
        browserID1.setText("BrowserID");
        browserID1.setToolTipText("Disable/Enable BrowserID");
        browserID1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                browserID1ActionPerformed(evt);
            }
        });

        saml1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        saml1.setSelected(true);
        saml1.setText("SAML");
        saml1.setToolTipText("Disable/Enable SAML");
        saml1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saml1ActionPerformed(evt);
            }
        });

        highlightSSO.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        highlightSSO.setSelected(true);
        highlightSSO.setText("Highlight SSO");
        highlightSSO.setToolTipText("Disable/Enable the highlighted messages in the Proxy tab.");
        highlightSSO.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                highlightSSOActionPerformed(evt);
            }
        });

        cryptoLabel1.setText("Cryptography");
        cryptoLabel1.setEnabled(false);

        schemaLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        schemaLabel1.setText("Schema:");
        schemaLabel1.setEnabled(false);

        schemaText1.setToolTipText("Insert a path to a schema file.");
        schemaText1.setEnabled(false);
        schemaText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                schemaText1ActionPerformed(evt);
            }
        });

        schemaOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        schemaOpen1.setText("...");
        schemaOpen1.setToolTipText("open file");
        schemaOpen1.setEnabled(false);
        schemaOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        schemaOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                schemaOpen1ActionPerformed(evt);
            }
        });

        certLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        certLabel1.setText("Certificate:");
        certLabel1.setEnabled(false);

        certText1.setToolTipText("Insert a path to a certificat file.");
        certText1.setEnabled(false);
        certText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                certText1ActionPerformed(evt);
            }
        });

        certOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        certOpen1.setText("...");
        certOpen1.setToolTipText("open file");
        certOpen1.setEnabled(false);
        certOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        certOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                certOpen1ActionPerformed(evt);
            }
        });

        privKeyLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        privKeyLabel1.setText("Private Key:");
        privKeyLabel1.setEnabled(false);

        privKeyText1.setToolTipText("Insert a path to a private key file.");
        privKeyText1.setEnabled(false);
        privKeyText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                privKeyText1ActionPerformed(evt);
            }
        });

        privKeyOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        privKeyOpen1.setText("...");
        privKeyOpen1.setToolTipText("open file");
        privKeyOpen1.setEnabled(false);
        privKeyOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        privKeyOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                privKeyOpen1ActionPerformed(evt);
            }
        });

        pubKeyLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        pubKeyLabel1.setText("Public Key:");
        pubKeyLabel1.setEnabled(false);

        pubKeyText1.setToolTipText("Insert a path to a public key file.");
        pubKeyText1.setEnabled(false);
        pubKeyText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pubKeyText1ActionPerformed(evt);
            }
        });

        pubKeyOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        pubKeyOpen1.setText("...");
        pubKeyOpen1.setToolTipText("open file");
        pubKeyOpen1.setEnabled(false);
        pubKeyOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        pubKeyOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pubKeyOpen1ActionPerformed(evt);
            }
        });

        scriptingLabel1.setText("Scripting");
        scriptingLabel1.setEnabled(false);

        scriptingDescription1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        scriptingDescription1.setText("The scripts are used as an interface to external attacking or processing libraries.");
        scriptingDescription1.setEnabled(false);

        scriptInLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        scriptInLabel1.setText("Input Processing Script:");
        scriptInLabel1.setEnabled(false);

        scriptInText1.setToolTipText("Insert a path to a python script.");
        scriptInText1.setEnabled(false);
        scriptInText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                scriptInText1ActionPerformed(evt);
            }
        });

        scriptInOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        scriptInOpen1.setText("...");
        scriptInOpen1.setToolTipText("open file");
        scriptInOpen1.setEnabled(false);
        scriptInOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        scriptInOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                scriptInOpen1ActionPerformed(evt);
            }
        });

        scriptOutLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        scriptOutLabel1.setText("Output Processing Script:");
        scriptOutLabel1.setEnabled(false);

        scriptOutText1.setToolTipText("Insert a path to a python script.");
        scriptOutText1.setEnabled(false);

        scriptOutOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        scriptOutOpen1.setText("...");
        scriptOutOpen1.setToolTipText("open file");
        scriptOutOpen1.setEnabled(false);
        scriptOutOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        scriptOutOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                scriptOutOpen1ActionPerformed(evt);
            }
        });

        extLibLabel1.setText("External Libraries");
        extLibLabel1.setEnabled(false);

        libLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        libLabel1.setText("Libraries:");
        libLabel1.setEnabled(false);

        libText1.setToolTipText("Insert a path to a .jar file.");
        libText1.setEnabled(false);
        libText1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                libText1ActionPerformed(evt);
            }
        });

        libOpen1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        libOpen1.setText("...");
        libOpen1.setToolTipText("open file");
        libOpen1.setEnabled(false);
        libOpen1.setMargin(new java.awt.Insets(0, 10, 0, 10));
        libOpen1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                libOpen1ActionPerformed(evt);
            }
        });

        saveConfLabel1.setText("Configurations");

        configLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        configLabel1.setText("Config file:");

        configText1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        configText1.setText("/no/path/found");

        configSave1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        configSave1.setText("Export");
        configSave1.setToolTipText("Save all data to the configuration file.");
        configSave1.setMargin(new java.awt.Insets(0, 14, 0, 14));
        configSave1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                configSave1ActionPerformed(evt);
            }
        });

        configImport.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        configImport.setText("Import");
        configImport.setMargin(new java.awt.Insets(0, 14, 0, 14));
        configImport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                configImportActionPerformed(evt);
            }
        });

        activeSSOProtocols.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        activeSSOProtocols.setSelected(true);
        activeSSOProtocols.setToolTipText("Disable all protocols");
        activeSSOProtocols.setMargin(new java.awt.Insets(0, 2, 0, 2));
        activeSSOProtocols.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                activeSSOProtocolsActionPerformed(evt);
            }
        });

        msAccount.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        msAccount.setSelected(true);
        msAccount.setText("Microsoft Account");
        msAccount.setToolTipText("Disable/Enable BrowserID");
        msAccount.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                msAccountActionPerformed(evt);
            }
        });

        configApply.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        configApply.setText("Apply");
        configApply.setToolTipText("Save all data to the configuration file.");
        configApply.setMargin(new java.awt.Insets(0, 14, 0, 14));
        configApply.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                configApplyActionPerformed(evt);
            }
        });

        logginglvlComboBox.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        logginglvlComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Info", "Debug", "Verbose" }));
        logginglvlComboBox.setSelectedIndex(2);
        logginglvlComboBox.setToolTipText("");
        logginglvlComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logginglvlComboBoxActionPerformed(evt);
            }
        });

        logginglvlLabel.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        logginglvlLabel.setText("Logging");

        hintLabel.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        hintLabel.setText("Hint:");

        hintTextLabel.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        hintTextLabel.setText("Show INFO and ERROR");

        loggingLabel.setText("Logging");

        javax.swing.GroupLayout scrollPanelLayout = new javax.swing.GroupLayout(scrollPanel);
        scrollPanel.setLayout(scrollPanelLayout);
        scrollPanelLayout.setHorizontalGroup(
            scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(scrollPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(scrollPanelLayout.createSequentialGroup()
                        .addComponent(libLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(libText1, javax.swing.GroupLayout.DEFAULT_SIZE, 450, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(libOpen1)
                        .addGap(515, 515, 515))
                    .addGroup(scrollPanelLayout.createSequentialGroup()
                        .addComponent(logginglvlLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(logginglvlComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(hintLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(hintTextLabel)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(scrollPanelLayout.createSequentialGroup()
                        .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(ssoLabel1)
                                .addGap(2, 2, 2)
                                .addComponent(activeSSOProtocols)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(ssoSeparator1))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(cryptoLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(cryptoSeparator1))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(scriptingLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(scriptingSeperator1))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(openIDConnect1)
                                    .addComponent(openID1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(facebookConnect)
                                    .addComponent(oAuth))
                                .addGap(18, 18, 18)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(scrollPanelLayout.createSequentialGroup()
                                        .addComponent(browserID1)
                                        .addGap(18, 18, 18)
                                        .addComponent(msAccount)
                                        .addGap(0, 0, Short.MAX_VALUE))
                                    .addGroup(scrollPanelLayout.createSequentialGroup()
                                        .addComponent(saml1)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(highlightSSO))))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(certLabel1)
                                    .addComponent(schemaLabel1)
                                    .addComponent(privKeyLabel1)
                                    .addComponent(pubKeyLabel1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(certText1)
                                    .addComponent(schemaText1)
                                    .addComponent(privKeyText1)
                                    .addComponent(pubKeyText1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(schemaOpen1, javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(certOpen1, javax.swing.GroupLayout.Alignment.TRAILING))
                                    .addComponent(privKeyOpen1)
                                    .addComponent(pubKeyOpen1)))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(scriptOutLabel1)
                                    .addComponent(scriptInLabel1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(scriptOutText1)
                                    .addComponent(scriptInText1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(scriptInOpen1, javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(scriptOutOpen1, javax.swing.GroupLayout.Alignment.TRAILING)))
                            .addComponent(scriptingDescription1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(extLibLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(extLibSeparator1))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(loggingLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(loggingSeparator))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(saveConfLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(saveConfSeparator1))
                            .addGroup(scrollPanelLayout.createSequentialGroup()
                                .addComponent(configLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(configText1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(configImport)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(configApply, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addGroup(scrollPanelLayout.createSequentialGroup()
                                        .addComponent(configSave1)
                                        .addGap(2, 2, 2)))))
                        .addContainerGap())))
        );
        scrollPanelLayout.setVerticalGroup(
            scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(scrollPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, scrollPanelLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(ssoSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(activeSSOProtocols)
                        .addComponent(ssoLabel1)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(oAuth)
                        .addComponent(browserID1)
                        .addComponent(msAccount))
                    .addComponent(openID1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(openIDConnect1)
                    .addComponent(facebookConnect)
                    .addComponent(saml1)
                    .addComponent(highlightSSO))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(cryptoLabel1)
                    .addComponent(cryptoSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 5, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(schemaLabel1)
                    .addComponent(schemaText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemaOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(certLabel1)
                    .addComponent(certText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(certOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(privKeyLabel1)
                    .addComponent(privKeyText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(privKeyOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(pubKeyLabel1)
                    .addComponent(pubKeyText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(pubKeyOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(scriptingLabel1)
                    .addComponent(scriptingSeperator1, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(scriptingDescription1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(scriptInLabel1)
                    .addComponent(scriptInText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(scriptInOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(scriptOutLabel1)
                    .addComponent(scriptOutText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(scriptOutOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(extLibLabel1)
                    .addComponent(extLibSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(libLabel1)
                    .addComponent(libText1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(libOpen1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(loggingSeparator, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(loggingLabel, javax.swing.GroupLayout.Alignment.TRAILING))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(logginglvlComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(hintTextLabel)
                    .addComponent(logginglvlLabel)
                    .addComponent(hintLabel))
                .addGap(18, 18, 18)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(saveConfSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(saveConfLabel1))
                .addGap(18, 18, 18)
                .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(configLabel1)
                        .addComponent(configText1))
                    .addGroup(scrollPanelLayout.createSequentialGroup()
                        .addGroup(scrollPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(configImport)
                            .addComponent(configSave1))
                        .addGap(18, 18, 18)
                        .addComponent(configApply)))
                .addContainerGap(164, Short.MAX_VALUE))
        );

        jScrollPane.setViewportView(scrollPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void openID1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openID1ActionPerformed
        openIDActive = openID1.isSelected();
    }//GEN-LAST:event_openID1ActionPerformed

    private void browserID1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_browserID1ActionPerformed
        browserIDActive = browserID1.isSelected();
    }//GEN-LAST:event_browserID1ActionPerformed

    private void saml1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saml1ActionPerformed
        samlActive = saml1.isSelected();
    }//GEN-LAST:event_saml1ActionPerformed

    private void schemaText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_schemaText1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_schemaText1ActionPerformed

    private void schemaOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_schemaOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            schema = fc.getSelectedFile();
            schemaText1.setText(schema.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            schemaText1.setText("File not found");
        }
    }//GEN-LAST:event_schemaOpen1ActionPerformed

    private void certText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_certText1ActionPerformed
        
    }//GEN-LAST:event_certText1ActionPerformed

    private void privKeyText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_privKeyText1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_privKeyText1ActionPerformed

    private void privKeyOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_privKeyOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            privkey = fc.getSelectedFile();
            privKeyText1.setText(privkey.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            privKeyText1.setText("File not found");
        }
    }//GEN-LAST:event_privKeyOpen1ActionPerformed

    private void pubKeyText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pubKeyText1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_pubKeyText1ActionPerformed

    private void pubKeyOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pubKeyOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           pubkey = fc.getSelectedFile();
           pubKeyText1.setText(pubkey.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            pubKeyText1.setText("File not found");
        }
    }//GEN-LAST:event_pubKeyOpen1ActionPerformed

    private void scriptInText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scriptInText1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_scriptInText1ActionPerformed

    private void scriptInOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scriptInOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           scriptIn = fc.getSelectedFile();
           scriptInText1.setText(scriptIn.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            scriptInText1.setText("File not found");
        }
    }//GEN-LAST:event_scriptInOpen1ActionPerformed

    private void libText1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_libText1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_libText1ActionPerformed

    private void libOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_libOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           extLib = fc.getSelectedFile();
           libText1.setText(extLib.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            libText1.setText("File not found");
        }
    }//GEN-LAST:event_libOpen1ActionPerformed

    private void configSave1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_configSave1ActionPerformed
        fc = new JFileChooser();
        File file;
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           file = fc.getSelectedFile();
        } else {
            return;
        }
        String path = file.getPath();
        exportConfig(path);
    }//GEN-LAST:event_configSave1ActionPerformed

    private void configImportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_configImportActionPerformed
        fc = new JFileChooser();
        File file;
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           file = fc.getSelectedFile();
        } else {
            return;
        }
        String path = file.getPath();
        importConfig(path);
    }//GEN-LAST:event_configImportActionPerformed

    private void certOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_certOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           cert = fc.getSelectedFile();
           certText1.setText(cert.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            certText1.setText("File not found");
        }
    }//GEN-LAST:event_certOpen1ActionPerformed

    private void scriptOutOpen1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scriptOutOpen1ActionPerformed
        fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
           scriptOut = fc.getSelectedFile();
           scriptOutText1.setText(scriptOut.getPath());
        } else {
            JOptionPane.showMessageDialog(this,"The selected file could not be found","File not found",JOptionPane.ERROR_MESSAGE);
            scriptOutText1.setText("File not found");
        }
    }//GEN-LAST:event_scriptOutOpen1ActionPerformed

    private void oAuthActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_oAuthActionPerformed
        oAuthActive = oAuth.isSelected();
    }//GEN-LAST:event_oAuthActionPerformed

    private void facebookConnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_facebookConnectActionPerformed
        facebookConnectActive = facebookConnect.isSelected();
    }//GEN-LAST:event_facebookConnectActionPerformed

    private void highlightSSOActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_highlightSSOActionPerformed
        highlightBool = highlightSSO.isSelected();
    }//GEN-LAST:event_highlightSSOActionPerformed

    private void activeSSOProtocolsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_activeSSOProtocolsActionPerformed
        boolean selected = activeSSOProtocols.isSelected();
        if(selected){
            oAuth.setEnabled(true);
            facebookConnect.setEnabled(true);
            saml1.setEnabled(true);
            openID1.setEnabled(true);
            openIDConnect1.setEnabled(true);
            browserID1.setEnabled(true);
            msAccount.setEnabled(true);
            
            oAuthActive = oAuth.isSelected();
            facebookConnectActive = facebookConnect.isSelected();
            samlActive = saml1.isSelected();
            openIDActive = openID1.isSelected();
            openIDConnectActive = openIDConnect1.isSelected();
            browserIDActive = browserID1.isSelected();
            msAccountActive = msAccount.isSelected();
        } else {
            oAuth.setEnabled(false);
            facebookConnect.setEnabled(false);
            saml1.setEnabled(false);
            openID1.setEnabled(false);
            openIDConnect1.setEnabled(false);
            browserID1.setEnabled(false);
            msAccount.setEnabled(false);
            
            oAuthActive = false;
            facebookConnectActive = false;
            samlActive = false;
            openIDActive = false;
            openIDConnectActive = false;
            browserIDActive = false;
            msAccountActive = false;
        }
    }//GEN-LAST:event_activeSSOProtocolsActionPerformed

    private void msAccountActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_msAccountActionPerformed
        msAccountActive = msAccount.isSelected();
    }//GEN-LAST:event_msAccountActionPerformed

    private void configApplyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_configApplyActionPerformed
        saveConfig();
    }//GEN-LAST:event_configApplyActionPerformed

    private void logginglvlComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logginglvlComboBoxActionPerformed
        LoggingLevel = logginglvlComboBox.getSelectedIndex();
        switch(LoggingLevel){
            case 0:
                hintTextLabel.setText("Show INFO and ERROR");
                break;
            case 1:
                hintTextLabel.setText("Show DEBUG and ERROR");
                break;
            case 2:
                hintTextLabel.setText("Show everything");
                break;
            default:
                hintTextLabel.setText("Error while Choosing.");
                Logging.getInstance().log(getClass(), "Variable LoggingLevel="+LoggingLevel, Logging.ERROR);
        }
    }//GEN-LAST:event_logginglvlComboBoxActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox activeSSOProtocols;
    private javax.swing.JCheckBox browserID1;
    private javax.swing.JLabel certLabel1;
    private javax.swing.JButton certOpen1;
    private javax.swing.JTextField certText1;
    private javax.swing.JButton configApply;
    private javax.swing.JButton configImport;
    private javax.swing.JLabel configLabel1;
    private javax.swing.JButton configSave1;
    private javax.swing.JLabel configText1;
    private javax.swing.JLabel cryptoLabel1;
    private javax.swing.JSeparator cryptoSeparator1;
    private javax.swing.JLabel extLibLabel1;
    private javax.swing.JSeparator extLibSeparator1;
    private javax.swing.JCheckBox facebookConnect;
    private javax.swing.JCheckBox highlightSSO;
    private javax.swing.JLabel hintLabel;
    private javax.swing.JLabel hintTextLabel;
    private javax.swing.JScrollPane jScrollPane;
    private javax.swing.JLabel libLabel1;
    private javax.swing.JButton libOpen1;
    private javax.swing.JTextField libText1;
    private javax.swing.JLabel loggingLabel;
    private javax.swing.JSeparator loggingSeparator;
    private javax.swing.JComboBox logginglvlComboBox;
    private javax.swing.JLabel logginglvlLabel;
    private javax.swing.JCheckBox msAccount;
    private javax.swing.JCheckBox oAuth;
    private javax.swing.JCheckBox openID1;
    private javax.swing.JCheckBox openIDConnect1;
    private javax.swing.JLabel privKeyLabel1;
    private javax.swing.JButton privKeyOpen1;
    private javax.swing.JTextField privKeyText1;
    private javax.swing.JLabel pubKeyLabel1;
    private javax.swing.JButton pubKeyOpen1;
    private javax.swing.JTextField pubKeyText1;
    private javax.swing.JCheckBox saml1;
    private javax.swing.JLabel saveConfLabel1;
    private javax.swing.JSeparator saveConfSeparator1;
    private javax.swing.JLabel schemaLabel1;
    private javax.swing.JButton schemaOpen1;
    private javax.swing.JTextField schemaText1;
    private javax.swing.JLabel scriptInLabel1;
    private javax.swing.JButton scriptInOpen1;
    private javax.swing.JTextField scriptInText1;
    private javax.swing.JLabel scriptOutLabel1;
    private javax.swing.JButton scriptOutOpen1;
    private javax.swing.JTextField scriptOutText1;
    private javax.swing.JLabel scriptingDescription1;
    private javax.swing.JLabel scriptingLabel1;
    private javax.swing.JSeparator scriptingSeperator1;
    private javax.swing.JPanel scrollPanel;
    private javax.swing.JLabel ssoLabel1;
    private javax.swing.JSeparator ssoSeparator1;
    // End of variables declaration//GEN-END:variables
    
    // This method hides all not used components
    // If it is sure that they are not used! Delete them!
    private void hideAllUnsedComponents(){
        cryptoLabel1.setVisible(false);
        cryptoSeparator1.setVisible(false);
        extLibSeparator1.setVisible(false);
        extLibLabel1.setVisible(false);
        libLabel1.setVisible(false);
        libOpen1.setVisible(false);
        libText1.setVisible(false);
        privKeyLabel1.setVisible(false);
        privKeyOpen1.setVisible(false);
        privKeyText1.setVisible(false);
        pubKeyLabel1.setVisible(false);
        pubKeyOpen1.setVisible(false);
        pubKeyText1.setVisible(false);
        schemaLabel1.setVisible(false);
        schemaOpen1.setVisible(false);
        schemaText1.setVisible(false);
        scriptInLabel1.setVisible(false);
        scriptInOpen1.setVisible(false);
        scriptInText1.setVisible(false);
        scriptOutLabel1.setVisible(false);
        scriptOutOpen1.setVisible(false);
        scriptOutText1.setVisible(false);
        scriptingDescription1.setVisible(false);
        scriptingLabel1.setVisible(false);
        scriptingSeperator1.setVisible(false);
        certLabel1.setVisible(false);
        certOpen1.setVisible(false);
        certText1.setVisible(false);
        // path to config file no longer necessary when using burp callbacks 
        configText1.setVisible(false);
        configLabel1.setVisible(false);
        
        //revalidate 
        this.revalidate();
    }
    
    /**
     * 
     * @return True if SAML is active, false otherwise.
     */
    public static boolean isSamlActive(){
        return samlActive;
    }
    
    /**
     * 
     * @return True if OpenID is active, false otherwise.
     */
    public static boolean isOpenIDActive(){
        return openIDActive;
    }
    
    /**
     * 
     * @return True if OpenID Connect is active, false otherwise.
     */
    public static boolean isOpenIDConnectActive(){
        return openIDConnectActive;
    }
    
    /**
     * 
     * @return True if BrowserID is active, false otherwise.
     */
    public static boolean isBrowserIDActive(){
        return browserIDActive;
    }
    
    /**
     * 
     * @return True if OAuth is active, false otherwise.
     */
    public static boolean isOAuthActive(){
        return oAuthActive;
    }
    
    /**
     * 
     * @return True if Facebook Connect is active, false otherwise.
     */
    public static boolean isFBConnectActive(){
        return facebookConnectActive;
    }
    
    /**
     * 
     * @return True if Mircosoft Account is active, false otherwise.
     */
    public static boolean isMSAccountActive(){
        return msAccountActive;
    }
    
    /**
     * 
     * @return True if the proxy history messages should be highlighted
     * is active, false otherwise.
     */
    public static boolean isHighlighted(){
        return highlightBool;
    }
    
    /**
     * Get the logging level.
     * 0 = Info, 1 = Debug, 2 = Verbose
     * @return The Logging level.
     */
    public static int getLoggingLevel(){
        return LoggingLevel;
    }

    private void saveConfig() {
        callbacks.saveExtensionSetting("SSOActive", Boolean.toString(activeSSOProtocols.isSelected()));
        callbacks.saveExtensionSetting("OpenIDActive", Boolean.toString(openID1.isSelected()));
        callbacks.saveExtensionSetting("OpenIDConnectActive", Boolean.toString(openIDConnect1.isSelected()));
        callbacks.saveExtensionSetting("OAuthActive", Boolean.toString(oAuth.isSelected()));
        callbacks.saveExtensionSetting("FacebookConnectActive", Boolean.toString(facebookConnect.isSelected()));
        callbacks.saveExtensionSetting("BrowserIDActive", Boolean.toString(browserID1.isSelected()));
        callbacks.saveExtensionSetting("SAMLActive", Boolean.toString(saml1.isSelected()));
        callbacks.saveExtensionSetting("MicrosoftAccountActive", Boolean.toString(msAccount.isSelected()));

        callbacks.saveExtensionSetting("HighlightActive", Boolean.toString(highlightBool));

        callbacks.saveExtensionSetting("Schema", schemaText1.getText());
        callbacks.saveExtensionSetting("Certificate", certText1.getText());
        callbacks.saveExtensionSetting("Private Key", privKeyText1.getText());
        callbacks.saveExtensionSetting("Public Key", pubKeyText1.getText());

        callbacks.saveExtensionSetting("Input Script", scriptInText1.getText());
        callbacks.saveExtensionSetting("Output Script", scriptOutText1.getText());

        callbacks.saveExtensionSetting("Libraries", libText1.getText());

//            callbacks.saveExtensionSetting("Config", path);

        callbacks.saveExtensionSetting("LogLvl", String.valueOf(LoggingLevel));
    }

    private void loadConfig() {
        openIDActive = Boolean.valueOf(callbacks.loadExtensionSetting("OpenIDActive"));
        openID1.setSelected(openIDActive);
        openIDConnectActive = Boolean.valueOf(callbacks.loadExtensionSetting("OpenIDConnectActive"));
        openIDConnect1.setSelected(openIDConnectActive);
        oAuthActive = Boolean.valueOf(callbacks.loadExtensionSetting("OAuthActive"));
        oAuth.setSelected(oAuthActive);
        facebookConnectActive = Boolean.valueOf(callbacks.loadExtensionSetting("FacebookConnectActive"));
        facebookConnect.setSelected(facebookConnectActive);
        browserIDActive = Boolean.valueOf(callbacks.loadExtensionSetting("BrowserIDActive"));
        browserID1.setSelected(browserIDActive);
        samlActive = Boolean.valueOf(callbacks.loadExtensionSetting("SAMLActive"));
        saml1.setSelected(samlActive);
        msAccountActive = Boolean.valueOf(callbacks.loadExtensionSetting("MicrosoftAccountActive"));
        msAccount.setSelected(msAccountActive);

        boolean asp = Boolean.valueOf(callbacks.loadExtensionSetting("SSOActive"));
        activeSSOProtocols.setSelected(asp);
        if(!asp){
            oAuth.setEnabled(false);
            facebookConnect.setEnabled(false);
            saml1.setEnabled(false);
            openID1.setEnabled(false);
            openIDConnect1.setEnabled(false);
            browserID1.setEnabled(false);
            msAccount.setEnabled(false);
        }

        highlightBool = Boolean.valueOf(callbacks.loadExtensionSetting("HighlightActive"));
        highlightSSO.setSelected(highlightBool);

        String str = callbacks.loadExtensionSetting("Schema");
        schemaText1.setText(str);
        str = callbacks.loadExtensionSetting("Certificate");
        certText1.setText(str);
        str = callbacks.loadExtensionSetting("Private Key");
        privKeyText1.setText(str);
        str = callbacks.loadExtensionSetting("Public Key");
        pubKeyText1.setText(str);

        str = callbacks.loadExtensionSetting("Input Script");
        scriptInText1.setText(str);
        str = callbacks.loadExtensionSetting("Output Script");
        scriptOutText1.setText(str);

        str = callbacks.loadExtensionSetting("Libraries");
        libText1.setText(str);

//                str = (String) json_conf.get("Config");

        LoggingLevel = Integer.parseInt(callbacks.loadExtensionSetting("LogLvl"));
        logginglvlComboBox.setSelectedIndex(LoggingLevel);
    }
    
}
