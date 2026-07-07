package de.sensler.soapui.attachmentsigning.core;

/**
 * The two Reference transforms defined by the WS-Security SwA Profile 1.1 for binding a
 * signature to a MIME attachment referenced via a "cid:" URI.
 */
public enum SwaTransformType {

    /**
     * Digests only the attachment's payload bytes (as delivered to the application, i.e. after
     * removing any Content-Transfer-Encoding). This is the recommended default: it is robust
     * against re-encoding/re-ordering of MIME headers performed by intermediaries or by SoapUI's
     * own HTTP transport when the message is put on the wire.
     */
    CONTENT(SwaConstants.ATTACHMENT_CONTENT_SIGNATURE_TRANSFORM),

    /**
     * Digests the complete MIME entity (headers, in canonical form, plus the encoded content).
     * Matches the SwA profile's "Complete" transform, but is fragile in practice because the
     * digest only verifies if the receiver reconstructs byte-identical MIME headers to the ones
     * assumed here.
     */
    COMPLETE(SwaConstants.ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM);

    private final String uri;

    SwaTransformType(String uri) {
        this.uri = uri;
    }

    public String getUri() {
        return uri;
    }

    public static SwaTransformType fromName(String name, SwaTransformType fallback) {
        if (name == null) {
            return fallback;
        }
        for (SwaTransformType type : values()) {
            if (type.name().equalsIgnoreCase(name)) {
                return type;
            }
        }
        return fallback;
    }
}
