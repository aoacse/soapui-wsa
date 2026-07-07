package com.artofarc.soapui.attachmentsigning.core;

import com.eviware.soapui.model.iface.Attachment;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Implements the "Attachment-Complete-Signature-Transform": the digest input is the MIME entity
 * for the attachment, i.e. its headers followed by a blank line and the (still encoded) content.
 *
 * <p>This is a best-effort reconstruction of the MIME headers SoapUI's HTTP transport will place
 * on the wire (Content-Type, Content-Transfer-Encoding, Content-ID). If the receiving verifier
 * assembles slightly different header bytes (e.g. header order/casing, folding), the digest will
 * not match even though the attachment itself is untouched - this is a known interoperability
 * weakness of the "Complete" transform in general, not specific to this plugin. Prefer {@link
 * SwaContentTransformService} unless the receiver specifically requires "Complete" semantics.
 */
public class SwaCompleteTransformService extends AbstractSwaTransformService {

    private static final String CRLF = "\r\n";

    @Override
    protected byte[] toOctets(AttachmentData attachmentData) {
        Attachment attachment = attachmentData.getAttachment();
        StringBuilder headers = new StringBuilder();
        headers.append("Content-Type: ").append(attachment.getContentType()).append(CRLF);
        headers.append("Content-Transfer-Encoding: binary").append(CRLF);
        String contentId = attachment.getContentID();
        if (contentId != null && contentId.length() > 0) {
            String normalized = AttachmentURIDereferencer.normalizeContentId(contentId);
            headers.append("Content-ID: <").append(normalized).append(">").append(CRLF);
        }
        headers.append(CRLF);

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(headers.toString().getBytes("US-ASCII"));
            out.write(attachmentData.getContent());
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
