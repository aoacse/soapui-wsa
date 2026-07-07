package de.sensler.soapui.attachmentsigning.filter;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.support.wss.WssCrypto;
import com.eviware.soapui.impl.wsdl.submit.filters.AbstractRequestFilter;
import com.eviware.soapui.model.iface.SubmitContext;
import com.eviware.soapui.plugins.auto.PluginRequestFilter;
import de.sensler.soapui.attachmentsigning.core.AttachmentSigner;
import de.sensler.soapui.attachmentsigning.core.SigningConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * When the "Automatically sign every attachment on every send" option (see {@link
 * SigningConfigDialog} in the {@code action} package) is enabled for a project, signs every
 * attachment on every outgoing HTTP request of that project right before it is sent - mirroring
 * how SoapUI's built-in Outgoing WS-Security configurations are auto-applied via {@code
 * WssRequestFilter}.
 */
@PluginRequestFilter(protocol = "http")
public class AutoSignAttachmentsRequestFilter extends AbstractRequestFilter {

    private static final Logger log = LogManager.getLogger(AutoSignAttachmentsRequestFilter.class);

    @Override
    public void filterWsdlRequest(SubmitContext context, WsdlRequest request) {
        try {
            if (request.getAttachmentCount() == 0) {
                return;
            }

            WsdlProject project = request.getOperation().getInterface().getProject();
            if (!SigningConfig.isAutoSignEnabled(project)) {
                return;
            }

            String cryptoName = SigningConfig.get(project, SigningConfig.CRYPTO, null);
            String alias = SigningConfig.get(project, SigningConfig.ALIAS, null);
            if (cryptoName == null || alias == null) {
                log.warn("Attachment auto-signing is enabled but no keystore/alias is configured; skipping");
                return;
            }
            WssCrypto wssCrypto = project.getWssContainer().getCryptoByName(cryptoName);
            if (wssCrypto == null) {
                log.warn("Attachment auto-signing: keystore '" + cryptoName + "' not found; skipping");
                return;
            }

            String password = SigningConfig.getExpandedPassword(project);
            String signed = AttachmentSigner.sign(request, wssCrypto, alias, password,
                    SigningConfig.getTransformType(project), null,
                    SigningConfig.isIncludeBodyAndTimestamp(project));
            request.setRequestContent(signed);
        } catch (Throwable e) {
            log.error("Attachment auto-signing failed", e);
            SoapUI.logError(e);
        }
    }
}
