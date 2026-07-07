package com.artofarc.soapui.attachmentsigning.core;

/**
 * Namespaces and algorithm URIs used for WS-Security SOAP-with-Attachments (SwA) Profile 1.1
 * signatures (http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1) and the surrounding
 * WS-Security X.509 Token Profile.
 */
public final class SwaConstants {

    public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    public static final String X509_V3_VALUE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public static final String BASE64_BINARY_ENCODING_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

    public static final String ATTACHMENT_CONTENT_SIGNATURE_TRANSFORM =
            "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";
    public static final String ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM =
            "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform";

    public static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private SwaConstants() {
    }
}
