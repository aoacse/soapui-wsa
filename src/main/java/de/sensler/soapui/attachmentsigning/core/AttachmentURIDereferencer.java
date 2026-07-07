package de.sensler.soapui.attachmentsigning.core;

import com.eviware.soapui.model.iface.Attachment;

import javax.xml.crypto.Data;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;

/**
 * Resolves the "cid:" URIs used by {@code ds:Reference} elements that sign attachments to the
 * actual attachment bytes, keyed by (unbracketed) Content-ID.
 */
public class AttachmentURIDereferencer implements URIDereferencer {

    private final Map<String, Attachment> attachmentsByContentId;

    public AttachmentURIDereferencer(Map<String, Attachment> attachmentsByContentId) {
        this.attachmentsByContentId = attachmentsByContentId;
    }

    public static String normalizeContentId(String contentId) {
        if (contentId == null) {
            return null;
        }
        String id = contentId.trim();
        if (id.startsWith("<") && id.endsWith(">")) {
            id = id.substring(1, id.length() - 1);
        }
        return id;
    }

    public static String toCidUri(String contentId) {
        String id = normalizeContentId(contentId);
        try {
            return "cid:" + URLDecoder.decode(id, "UTF-8").replace(" ", "%20");
        } catch (UnsupportedEncodingException e) {
            return "cid:" + id;
        }
    }

    @Override
    public Data dereference(URIReference reference, XMLCryptoContext context) throws URIReferenceException {
        String uri = reference.getURI();
        if (uri == null || !uri.startsWith("cid:")) {
            throw new URIReferenceException("Unsupported URI for attachment signing: " + uri);
        }

        String cid;
        try {
            cid = URLDecoder.decode(uri.substring("cid:".length()), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            cid = uri.substring("cid:".length());
        }

        Attachment attachment = attachmentsByContentId.get(cid);
        if (attachment == null) {
            throw new URIReferenceException("No attachment found for Content-ID '" + cid + "'");
        }

        try {
            return new AttachmentData(attachment, readFully(attachment.getInputStream()));
        } catch (Exception e) {
            throw new URIReferenceException("Failed to read content of attachment '" + cid + "'", e);
        }
    }

    private static byte[] readFully(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }
}
