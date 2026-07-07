package de.sensler.soapui.attachmentsigning.core;

/**
 * Implements the "Attachment-Content-Signature-Transform": the digest input is exactly the
 * attachment's payload bytes, with no MIME framing at all. Registered under {@link
 * SwaConstants#ATTACHMENT_CONTENT_SIGNATURE_TRANSFORM} by {@link SwaTransformProvider}.
 */
public class SwaContentTransformService extends AbstractSwaTransformService {

    @Override
    protected byte[] toOctets(AttachmentData data) {
        return data.getContent();
    }
}
