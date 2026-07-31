package com.artofarc.soapui.attachmentsigning;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.plugins.PluginAdapter;
import com.eviware.soapui.plugins.PluginConfiguration;
import com.eviware.soapui.ui.desktop.NullDesktop;
import com.eviware.soapui.ui.desktop.SoapUIDesktop;
import com.artofarc.soapui.attachmentsigning.action.RequestToolbarButtonInjector;

import javax.swing.Timer;

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

    // Plugins are initialized from DefaultSoapUICore.init() -> loadPlugins(), which runs well before
    // SoapUI.show(Workspace) builds the real UI and installs the real SoapUIDesktop. Calling
    // SoapUI.getDesktop() this early only ever returns a NullDesktop placeholder that never fires
    // desktopPanelCreated - registering on it silently loses the toolbar button forever. Poll until
    // the real desktop is installed instead (or give up after a while, e.g. headless/command-line
    // mode, where there is no desktop to add a button to).
    private static final int DESKTOP_POLL_INTERVAL_MILLIS = 500;
    private static final int DESKTOP_POLL_MAX_ATTEMPTS = 120; // ~1 minute

    @Override
    public void initialize() {
        super.initialize();
        // Not a SoapUIListener, so it can't be auto-registered via @ListenerConfiguration like the
        // plugin's other listeners - wire it up manually here instead. Guarded so that if this ever
        // fails, it only costs the toolbar button, not the rest of the plugin (the context-menu
        // action and auto-signing don't depend on this).
        try {
            attachToolbarButtonInjectorWhenDesktopReady(0);
        } catch (Throwable e) {
            SoapUI.logError(e);
        }
    }

    private static void attachToolbarButtonInjectorWhenDesktopReady(int attempt) {
        SoapUIDesktop desktop = SoapUI.getDesktop();
        if (!(desktop instanceof NullDesktop)) {
            desktop.addDesktopListener(new RequestToolbarButtonInjector());
            SoapUI.log("Attachment Signing Plugin: toolbar button listener registered with " + desktop.getClass().getName());
            return;
        }
        if (attempt >= DESKTOP_POLL_MAX_ATTEMPTS) {
            SoapUI.log("Attachment Signing Plugin: no desktop UI became available, toolbar button will not be added");
            return;
        }
        Timer timer = new Timer(DESKTOP_POLL_INTERVAL_MILLIS,
                event -> attachToolbarButtonInjectorWhenDesktopReady(attempt + 1));
        timer.setRepeats(false);
        timer.start();
    }
}
