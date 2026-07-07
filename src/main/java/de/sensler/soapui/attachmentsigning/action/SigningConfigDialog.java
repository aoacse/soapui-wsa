package de.sensler.soapui.attachmentsigning.action;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.support.wss.WssCrypto;
import com.eviware.soapui.model.iface.Attachment;
import com.eviware.soapui.support.UISupport;
import de.sensler.soapui.attachmentsigning.core.AttachmentSigner;
import de.sensler.soapui.attachmentsigning.core.SigningConfig;
import de.sensler.soapui.attachmentsigning.core.SwaTransformType;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lets the user pick a keystore/alias/transform for signing this request's attachments, either
 * once ("Sign Now") or persistently for the whole project ("Save Settings", optionally with
 * "sign automatically on every send").
 */
public class SigningConfigDialog extends JDialog {

    private final WsdlProject project;
    private final WsdlRequest request;

    private JComboBox<String> cryptoCombo;
    private JTextField aliasField;
    private JPasswordField passwordField;
    private JComboBox<SwaTransformType> transformCombo;
    private JCheckBox includeBodyAndTimestampCheckBox;
    private JCheckBox autoSignCheckBox;
    private List<JCheckBox> attachmentCheckBoxes = new ArrayList<>();

    public SigningConfigDialog(Frame owner, WsdlProject project, WsdlRequest request) {
        super(owner, "Sign Attachments (WS-Security SwA)", true);
        this.project = project;
        this.request = request;
        buildUI();
        loadFromConfig();
        pack();
        setLocationRelativeTo(owner);
    }

    private void buildUI() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Keystore:"), c);
        cryptoCombo = new JComboBox<>(project.getWssContainer().getCryptoNames());
        cryptoCombo.setEditable(true);
        c.gridx = 1;
        form.add(cryptoCombo, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Key alias:"), c);
        aliasField = new JTextField(20);
        c.gridx = 1;
        c.gridy = row;
        form.add(aliasField, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Key password:"), c);
        passwordField = new JPasswordField(20);
        c.gridx = 1;
        c.gridy = row;
        form.add(passwordField, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Transform:"), c);
        transformCombo = new JComboBox<>(SwaTransformType.values());
        transformCombo.setRenderer((list, value, index, isSelected, cellHasFocus) ->
                new JLabel(value == SwaTransformType.CONTENT ? "Content (recommended)" : "Complete (MIME entity)"));
        c.gridx = 1;
        c.gridy = row;
        form.add(transformCombo, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Attachments:"), c);
        JPanel attachmentsPanel = new JPanel();
        attachmentsPanel.setLayout(new BoxLayout(attachmentsPanel, BoxLayout.Y_AXIS));
        Attachment[] attachments = request.getAttachments();
        if (attachments == null || attachments.length == 0) {
            attachmentsPanel.add(new JLabel("(this request has no attachments)"));
        } else {
            for (Attachment attachment : attachments) {
                JCheckBox cb = new JCheckBox(attachment.getName() + "  [" + attachment.getContentID() + "]", true);
                attachmentCheckBoxes.add(cb);
                attachmentsPanel.add(cb);
            }
        }
        c.gridx = 1;
        c.gridy = row;
        form.add(attachmentsPanel, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        includeBodyAndTimestampCheckBox = new JCheckBox("Also sign message Body + Timestamp (standard WS-Security, "
                + "combined into the same signature)");
        form.add(includeBodyAndTimestampCheckBox, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        autoSignCheckBox = new JCheckBox("Automatically sign every attachment on every send (whole project)");
        form.add(autoSignCheckBox, c);
        row++;
        c.gridwidth = 1;

        JButton signNowButton = new JButton("Sign Now");
        signNowButton.addActionListener(e -> signNow());

        JButton saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> {
            saveToConfig();
            dispose();
        });

        JButton cancelButton = new JButton("Close");
        cancelButton.addActionListener(e -> dispose());

        JPanel buttons = new JPanel();
        buttons.add(signNowButton);
        buttons.add(saveButton);
        buttons.add(cancelButton);

        JPanel content = new JPanel(new BorderLayout());
        content.add(form, BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        setContentPane(content);
    }

    private void loadFromConfig() {
        String crypto = SigningConfig.get(project, SigningConfig.CRYPTO, null);
        if (crypto != null) {
            cryptoCombo.setSelectedItem(crypto);
        }
        aliasField.setText(SigningConfig.get(project, SigningConfig.ALIAS, ""));
        passwordField.setText(SigningConfig.get(project, SigningConfig.PASSWORD, ""));
        transformCombo.setSelectedItem(SigningConfig.getTransformType(project));
        includeBodyAndTimestampCheckBox.setSelected(SigningConfig.isIncludeBodyAndTimestamp(project));
        autoSignCheckBox.setSelected(SigningConfig.isAutoSignEnabled(project));
    }

    private void saveToConfig() {
        SigningConfig.set(project, SigningConfig.CRYPTO, (String) cryptoCombo.getSelectedItem());
        SigningConfig.set(project, SigningConfig.ALIAS, aliasField.getText());
        SigningConfig.set(project, SigningConfig.PASSWORD, new String(passwordField.getPassword()));
        SigningConfig.set(project, SigningConfig.TRANSFORM, ((SwaTransformType) transformCombo.getSelectedItem()).name());
        SigningConfig.set(project, SigningConfig.INCLUDE_BODY_TIMESTAMP,
                Boolean.toString(includeBodyAndTimestampCheckBox.isSelected()));
        SigningConfig.set(project, SigningConfig.AUTO_SIGN, Boolean.toString(autoSignCheckBox.isSelected()));
    }

    private void signNow() {
        String cryptoName = (String) cryptoCombo.getSelectedItem();
        WssCrypto wssCrypto = cryptoName == null ? null : project.getWssContainer().getCryptoByName(cryptoName);
        if (wssCrypto == null) {
            UISupport.showErrorMessage("Please select a valid Keystore (configure one under "
                    + "Project > WS-Security Configurations > Keystores first).");
            return;
        }

        List<String> selectedContentIds = new ArrayList<>();
        Attachment[] attachments = request.getAttachments();
        for (int i = 0; i < attachmentCheckBoxes.size(); i++) {
            if (attachmentCheckBoxes.get(i).isSelected()) {
                selectedContentIds.add(attachments[i].getContentID());
            }
        }
        if (selectedContentIds.isEmpty()) {
            UISupport.showErrorMessage("Select at least one attachment to sign.");
            return;
        }

        try {
            UISupport.setHourglassCursor();
            String signed = AttachmentSigner.sign(request.getRequestContent(), request, wssCrypto, aliasField.getText(),
                    new String(passwordField.getPassword()),
                    (SwaTransformType) transformCombo.getSelectedItem(), selectedContentIds,
                    includeBodyAndTimestampCheckBox.isSelected());
            request.setRequestContent(signed);
            UISupport.showInfoMessage("Signed " + selectedContentIds.size() + " attachment(s)"
                    + (includeBodyAndTimestampCheckBox.isSelected() ? " plus Body + Timestamp." : "."));
        } catch (Throwable e) {
            UISupport.showErrorMessage(e.toString());
        } finally {
            UISupport.resetCursor();
        }
    }
}
