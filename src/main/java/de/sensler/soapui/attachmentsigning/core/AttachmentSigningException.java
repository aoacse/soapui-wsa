package de.sensler.soapui.attachmentsigning.core;

/** Raised for configuration/usage errors detected while signing attachments (missing key, etc). */
public class AttachmentSigningException extends Exception {

    public AttachmentSigningException(String message) {
        super(message);
    }

    public AttachmentSigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
