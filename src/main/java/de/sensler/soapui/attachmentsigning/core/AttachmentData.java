package de.sensler.soapui.attachmentsigning.core;

import com.eviware.soapui.model.iface.Attachment;

import javax.xml.crypto.Data;

/**
 * Wraps a SoapUI {@link Attachment} together with its raw bytes so that it can flow through the
 * JSR 105 (javax.xml.crypto.dsig) Reference/Transform pipeline: {@link AttachmentURIDereferencer}
 * produces it for a "cid:" URI, and {@link AbstractSwaTransformService} consumes it to produce the
 * octet stream that is actually digested.
 */
public class AttachmentData implements Data {

    private final Attachment attachment;
    private final byte[] content;

    public AttachmentData(Attachment attachment, byte[] content) {
        this.attachment = attachment;
        this.content = content;
    }

    public Attachment getAttachment() {
        return attachment;
    }

    public byte[] getContent() {
        return content;
    }
}
