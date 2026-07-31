package com.artofarc.soapui.attachmentsigning.filter;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.submit.transports.http.BaseHttpRequestTransport;
import com.eviware.soapui.impl.wsdl.support.wss.WssCrypto;
import com.eviware.soapui.impl.wsdl.submit.filters.AbstractRequestFilter;
import com.eviware.soapui.model.iface.SubmitContext;
import com.eviware.soapui.impl.wsdl.support.wss.entries.SignatureEntry;
import com.eviware.soapui.model.propertyexpansion.DefaultPropertyExpansionContext;
import com.eviware.soapui.model.propertyexpansion.PropertyExpansionContext;
import com.eviware.soapui.plugins.auto.PluginRequestFilter;
import com.artofarc.soapui.attachmentsigning.core.AttachmentSigner;
import com.artofarc.soapui.attachmentsigning.core.NativeSignatureSource;
import com.artofarc.soapui.attachmentsigning.core.SigningConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * When the "Automatically sign every attachment on every send" option (see {@link
 * SigningConfigDialog} in the {@code action} package) is enabled for a project, signs every
 * attachment on every outgoing HTTP request of that project right before it is sent.
 *
 * <p>Plugin request filters are registered after all of SoapUI's built-in ones (including {@code
 * WssRequestFilter}, which applies the project's native "Sign"/"Timestamp" Outgoing WSS
 * configuration), so this filter always runs afterwards in the same submission. Like {@code
 * WssRequestFilter} itself, it reads and writes the outgoing XML via the {@code SubmitContext}'s
 * {@link BaseHttpRequestTransport#REQUEST_CONTENT} property rather than {@code
 * request.getRequestContent()}/{@code setRequestContent()} - that property is what actually goes
 * out on the wire for this one submission, and by the time this filter runs it already reflects
 * whatever native WSS signing was just applied, including any {@code wsse:Security} header it
 * created. Signing that (rather than the request's saved, pre-native-WSS content) means the
 * attachment signature lands in the very same header, next to the native one, instead of being
 * silently dropped or applied to stale content - and, unlike touching the saved request, doing
 * this only for the outgoing copy means repeated sends don't keep stacking up signatures.
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
            String password = SigningConfig.getExpandedPassword(project);

            if (cryptoName == null || alias == null) {
                // Not explicitly configured for this plugin - fall back to whatever keystore/alias
                // the request's own Outgoing WSS "Signature" entry already uses, so attachment
                // signing works out of the box wherever native WSS signing is already set up.
                SignatureEntry nativeEntry = NativeSignatureSource.findSignatureEntry(request);
                if (nativeEntry != null) {
                    cryptoName = nativeEntry.getCrypto();
                    alias = nativeEntry.getUsername();
                    PropertyExpansionContext expansionContext = new DefaultPropertyExpansionContext(project);
                    password = expansionContext.expand(nativeEntry.getPassword());
                }
            }

            if (cryptoName == null || alias == null) {
                warn("Attachment auto-signing is enabled but no keystore/alias is configured "
                        + "(neither explicitly for this plugin, nor via the request's Outgoing WSS "
                        + "Signature entry); skipping");
                return;
            }
            WssCrypto wssCrypto = project.getWssContainer().getCryptoByName(cryptoName);
            if (wssCrypto == null) {
                warn("Attachment auto-signing: keystore '" + cryptoName + "' not found; skipping");
                return;
            }

            String requestXml = (String) context.getProperty(BaseHttpRequestTransport.REQUEST_CONTENT);
            if (requestXml == null) {
                requestXml = request.getRequestContent();
            }

            String signed = AttachmentSigner.sign(requestXml, request, wssCrypto, alias, password,
                    SigningConfig.getTransformType(project), null,
                    SigningConfig.isIncludeBodyAndTimestamp(project));
            context.setProperty(BaseHttpRequestTransport.REQUEST_CONTENT, signed);
        } catch (Throwable e) {
            log.error("Attachment auto-signing failed", e);
            SoapUI.logError(e);
        }
    }

    private static void warn(String message) {
        log.warn(message);
        // See AttachmentSigner.sign() for why this is needed in addition to the log4j2 call above.
        SoapUI.log(message);
    }
}
