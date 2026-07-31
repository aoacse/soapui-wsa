package com.artofarc.soapui.attachmentsigning.action;

import com.eviware.soapui.impl.support.panels.AbstractHttpRequestDesktopPanel;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.teststeps.WsdlTestRequestStep;
import com.eviware.soapui.model.ModelItem;
import com.eviware.soapui.support.UISupport;
import com.eviware.soapui.ui.desktop.DesktopPanel;
import com.eviware.soapui.ui.support.DesktopListenerAdapter;

import javax.swing.JButton;
import java.awt.Component;
import java.awt.Container;

/**
 * Adds a small "Sign Attachments..." button to the request editor's toolbar, right next to the
 * Submit button, on every SOAP request desktop panel as it's created. There is no dedicated plugin
 * extension point for that toolbar (SoapUI builds it via hardcoded {@code insertButtons(...)}
 * overrides in its own desktop panel classes) - this instead listens for {@link
 * com.eviware.soapui.ui.desktop.DesktopListener#desktopPanelCreated}, which SoapUI fires for every
 * opened editor, and inserts the button using only the panel's public {@code getSubmitButton()}
 * and standard {@code java.awt.Container} methods (no reflection into private fields).
 *
 * <p>{@code DesktopListener} isn't a {@code SoapUIListener}, so it can't be auto-registered via
 * {@code @ListenerConfiguration} like the plugin's other listeners; instead an instance of this
 * class is registered once with {@code SoapUI.getDesktop()} from {@link
 * com.artofarc.soapui.attachmentsigning.PluginConfig#initialize()}.
 */
public class RequestToolbarButtonInjector extends DesktopListenerAdapter {

    private static final String BUTTON_NAME = "com.artofarc.soapui.attachmentsigning.signButton";
    private static final String KEY_GLYPH = "🔑";

    @Override
    public void desktopPanelCreated(DesktopPanel desktopPanel) {
        if (!(desktopPanel instanceof AbstractHttpRequestDesktopPanel)) {
            return;
        }

        WsdlRequest request = resolveRequest(desktopPanel.getModelItem());
        if (request == null) {
            return;
        }

        JButton submitButton = ((AbstractHttpRequestDesktopPanel<?, ?>) desktopPanel).getSubmitButton();
        if (submitButton == null) {
            return;
        }
        Container toolbar = submitButton.getParent();
        if (toolbar == null || alreadyInjected(toolbar)) {
            return;
        }

        JButton signButton = new JButton(KEY_GLYPH);
        signButton.setName(BUTTON_NAME);
        signButton.setToolTipText("Sign Attachments (WS-Security SwA)...");
        signButton.addActionListener(event -> {
            WsdlProject project = request.getOperation().getInterface().getProject();
            new SigningConfigDialog(UISupport.getMainFrame(), project, request).setVisible(true);
        });

        int submitIndex = indexOf(toolbar, submitButton);
        toolbar.add(signButton, submitIndex < 0 ? -1 : submitIndex + 1);
        toolbar.revalidate();
        toolbar.repaint();
    }

    private static boolean alreadyInjected(Container toolbar) {
        for (Component component : toolbar.getComponents()) {
            if (BUTTON_NAME.equals(component.getName())) {
                return true;
            }
        }
        return false;
    }

    private static int indexOf(Container container, Component component) {
        Component[] components = container.getComponents();
        for (int i = 0; i < components.length; i++) {
            if (components[i] == component) {
                return i;
            }
        }
        return -1;
    }

    private static WsdlRequest resolveRequest(ModelItem modelItem) {
        if (modelItem instanceof WsdlRequest) {
            return (WsdlRequest) modelItem;
        }
        if (modelItem instanceof WsdlTestRequestStep) {
            return ((WsdlTestRequestStep) modelItem).getTestRequest();
        }
        return null;
    }
}
