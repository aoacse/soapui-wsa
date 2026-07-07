package com.artofarc.soapui.attachmentsigning.core;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.support.wss.OutgoingWss;
import com.eviware.soapui.impl.wsdl.support.wss.WssContainer;
import com.eviware.soapui.impl.wsdl.support.wss.WssEntry;
import com.eviware.soapui.impl.wsdl.support.wss.entries.SignatureEntry;

/**
 * Looks up the keystore/alias/password already configured in the request's assigned Outgoing WSS
 * "Signature" entry (Project > WS-Security Configurations), so attachment signing can default to
 * the exact same key material native WSS uses for the Body/Timestamp signature - no separate,
 * duplicate configuration needed for the common case of signing with the same identity.
 */
public final class NativeSignatureSource {

    private NativeSignatureSource() {
    }

    /**
     * Returns the first "Signature" entry of the Outgoing WSS configuration currently assigned to
     * {@code request} (the same one SoapUI's native WssRequestFilter would apply), or {@code null}
     * if the request has no assigned Outgoing WSS config or that config has no Signature entry.
     */
    public static SignatureEntry findSignatureEntry(WsdlRequest request) {
        WssContainer wssContainer = request.getOperation().getInterface().getProject().getWssContainer();
        if (wssContainer == null) {
            return null;
        }
        OutgoingWss outgoingWss = wssContainer.getOutgoingWssByName(request.getOutgoingWss());
        if (outgoingWss == null) {
            return null;
        }
        for (WssEntry entry : outgoingWss.getEntries()) {
            if (entry instanceof SignatureEntry) {
                return (SignatureEntry) entry;
            }
        }
        return null;
    }
}
