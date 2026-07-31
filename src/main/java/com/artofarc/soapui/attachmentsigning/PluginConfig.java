package com.artofarc.soapui.attachmentsigning;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.plugins.PluginAdapter;
import com.eviware.soapui.plugins.PluginConfiguration;
import com.artofarc.soapui.attachmentsigning.action.RequestToolbarButtonInjector;

/**
 * Adds WS-Security SOAP-with-Attachments (SwA) signing of MIME attachments to SoapUI: a "Sign
 * Attachments..." action on both plain interface-level Requests and SOAP Test Request steps, a
 * matching toolbar button in the request editor, and an optional per-project auto-sign-on-send
 * mode. See the plugin's README for setup instructions.
 */
@PluginConfiguration(groupId = "com.artofarc.soapui.plugins", name = "Attachment Signing Plugin", version = "1.0.0",
        autoDetect = true, description = "Signs SOAP/MTOM attachments using WS-Security SwA Profile 1.1 (X.509 signature)",
        infoUrl = "https://github.com/aoacse/soapui-wsa")
public class PluginConfig extends PluginAdapter {

    @Override
    public void initialize() {
        super.initialize();
        // Not a SoapUIListener, so it can't be auto-registered via @ListenerConfiguration like the
        // plugin's other listeners - wire it up manually here instead.
        SoapUI.getDesktop().addDesktopListener(new RequestToolbarButtonInjector());
    }
}
