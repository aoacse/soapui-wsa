package com.artofarc.soapui.attachmentsigning.core;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.support.wss.WssCrypto;
import com.eviware.soapui.model.iface.Attachment;
import com.eviware.soapui.support.xml.XmlUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Signs one or more of a {@link WsdlRequest}'s MIME attachments with a WS-Security SwA Profile 1.1
 * signature: a {@code wsse:Security} header containing an X.509 {@code BinarySecurityToken} and a
 * {@code ds:Signature} with one {@code ds:Reference} per signed attachment (URI {@code cid:...},
 * transform {@link SwaTransformType#getUri()}). Optionally also covers the SOAP Body and a fresh
 * {@code wsu:Timestamp} with plain Exclusive-C14N references, matching what SoapUI's own built-in
 * "Sign" + "Timestamp" Outgoing WSS entries produce - so the message-level and attachment
 * signatures can be combined into a single {@code ds:Signature} instead of requiring both
 * mechanisms to be configured and applied separately.
 *
 * <p>The private key and certificate are taken from one of the project's existing WS-Security
 * Keystores ({@link WssCrypto}), so key material is managed exactly the way SoapUI's built-in
 * "Outgoing WS-Security Configurations" already do.
 */
public final class AttachmentSigner {

    private static final Logger log = LogManager.getLogger(AttachmentSigner.class);

    private static final long TIMESTAMP_TTL_SECONDS = 300;
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(java.time.ZoneOffset.UTC);

    private AttachmentSigner() {
    }

    /**
     * Signs the given attachments into {@code requestXml} and returns the resulting XML. Takes the
     * XML to sign as an explicit parameter - rather than reading {@code request.getRequestContent()}
     * itself - so callers can sign whatever the actual outgoing content currently is: the request
     * editor's persisted content (manual "Sign Now"), or the transient per-submission copy held in
     * the {@code SubmitContext} that other request filters (notably SoapUI's own native
     * "Sign"+"Timestamp" Outgoing WSS, applied earlier in the same submission) may have already
     * added a {@code wsse:Security} header to - which this method then reuses and adds an
     * attachment {@code ds:Signature} into, rather than clobbering or ignoring it.
     *
     * @param contentIdsToSign Content-IDs (with or without angle brackets) of the attachments to
     *                          sign, or {@code null}/empty to sign every attachment on the request.
     * @param includeBodyAndTimestamp if true, also adds (or reuses an existing) {@code
     *                          wsu:Timestamp} and signs it together with the SOAP Body, in the
     *                          same {@code ds:Signature} as the attachments. Leave false if this is
     *                          already covered by SoapUI's own Outgoing WSS configuration.
     */
    public static String sign(String requestXml, WsdlRequest request, WssCrypto wssCrypto, String alias,
                               String password, SwaTransformType transformType, Collection<String> contentIdsToSign,
                               boolean includeBodyAndTimestamp) throws Exception {
        Attachment[] attachments = request.getAttachments();
        if (attachments == null || attachments.length == 0) {
            throw new AttachmentSigningException("Request has no attachments to sign");
        }

        Map<String, Attachment> byContentId = new HashMap<>();
        for (Attachment attachment : attachments) {
            String id = AttachmentURIDereferencer.normalizeContentId(attachment.getContentID());
            if (id != null) {
                byContentId.put(id, attachment);
            }
        }

        List<String> idsToSign = new ArrayList<>();
        if (contentIdsToSign == null || contentIdsToSign.isEmpty()) {
            idsToSign.addAll(byContentId.keySet());
        } else {
            for (String id : contentIdsToSign) {
                idsToSign.add(AttachmentURIDereferencer.normalizeContentId(id));
            }
        }
        if (idsToSign.isEmpty()) {
            throw new AttachmentSigningException("No attachments selected to sign");
        }
        for (String id : idsToSign) {
            if (!byContentId.containsKey(id)) {
                throw new AttachmentSigningException("Attachment with Content-ID '" + id + "' not found on request");
            }
        }

        PrivateKey privateKey = resolvePrivateKey(wssCrypto, alias, password);
        X509Certificate certificate = resolveCertificate(wssCrypto, alias);

        SwaTransformProvider.install();

        Document doc = XmlUtils.parseXml(requestXml);
        Element envelope = doc.getDocumentElement();
        String soapNs = envelope.getNamespaceURI();

        Element body = firstChildElementNS(envelope, soapNs, "Body");
        if (body == null) {
            throw new AttachmentSigningException("Request content is not a SOAP envelope (no Body found)");
        }
        Element header = firstChildElementNS(envelope, soapNs, "Header");
        if (header == null) {
            header = doc.createElementNS(soapNs, qualify(envelope, "Header"));
            envelope.insertBefore(header, body);
        }

        Element security = firstChildElementNS(header, SwaConstants.WSSE_NS, "Security");
        if (security == null) {
            security = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:Security");
            header.insertBefore(security, header.getFirstChild());
        }

        String bstId = findOrCreateBst(doc, security, certificate);

        Element str = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:SecurityTokenReference");
        Element strRef = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:Reference");
        strRef.setAttribute("URI", "#" + bstId);
        strRef.setAttribute("ValueType", SwaConstants.X509_V3_VALUE_TYPE);
        str.appendChild(strRef);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        DigestMethod digestMethod = fac.newDigestMethod(SwaConstants.DIGEST_SHA256, null);
        Transform exclusiveC14nTransform = fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null);

        List<Reference> references = new ArrayList<>();
        for (String cid : idsToSign) {
            Transform transform = fac.newTransform(transformType.getUri(), (TransformParameterSpec) null);
            references.add(fac.newReference(AttachmentURIDereferencer.toCidUri(cid), digestMethod,
                    Collections.singletonList(transform), null, null));
        }

        if (includeBodyAndTimestamp) {
            String bodyId = getOrCreateWsuId(body, "id-");
            references.add(fac.newReference("#" + bodyId, digestMethod,
                    Collections.singletonList(exclusiveC14nTransform), null, null));

            Element timestamp = getOrCreateTimestamp(doc, security);
            String timestampId = timestamp.getAttributeNS(SwaConstants.WSU_NS, "Id");
            references.add(fac.newReference("#" + timestampId, digestMethod,
                    Collections.singletonList(exclusiveC14nTransform), null, null));
        }

        CanonicalizationMethod c14n = fac.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = fac.newSignatureMethod(SwaConstants.SIGNATURE_RSA_SHA256, null);
        SignedInfo signedInfo = fac.newSignedInfo(c14n, signatureMethod, references);

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(new DOMStructure(str)));

        XMLSignature signature = fac.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext signContext = new DOMSignContext(privateKey, security);
        signContext.setURIDereferencer(new AttachmentURIDereferencer(byContentId, fac.getURIDereferencer()));
        signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");
        signature.sign(signContext);

        String summary = "Signed attachment(s) [" + String.join(", ", idsToSign) + "] of request '" + request.getName()
                + "' using transform " + transformType + ", keystore '" + wssCrypto.getLabel() + "', alias '" + alias
                + "'" + (includeBodyAndTimestamp ? " (also covering Body + Timestamp)" : "");
        log.info(summary);
        // SoapUI.log(...) goes straight to the visible Log panel regardless of log4j2 level/appender
        // configuration for this (unconfigured, third-party) logger category - log.info() above may
        // not actually be visible anywhere depending on that configuration, so don't rely on it alone.
        SoapUI.log(summary);

        StringWriter writer = new StringWriter();
        XmlUtils.serialize(doc, writer);
        return writer.toString();
    }

    private static PrivateKey resolvePrivateKey(WssCrypto wssCrypto, String alias, String password) throws Exception {
        Crypto crypto = wssCrypto.getCrypto();
        PrivateKey key = crypto.getPrivateKey(alias, password);
        if (key == null) {
            throw new AttachmentSigningException("No private key found for alias '" + alias + "' in keystore '"
                    + wssCrypto.getLabel() + "'");
        }
        return key;
    }

    private static X509Certificate resolveCertificate(WssCrypto wssCrypto, String alias) throws Exception {
        Crypto crypto = wssCrypto.getCrypto();
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(alias);
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        if (certs == null || certs.length == 0) {
            throw new AttachmentSigningException("No certificate found for alias '" + alias + "' in keystore '"
                    + wssCrypto.getLabel() + "'");
        }
        return certs[0];
    }

    /**
     * Reuses an existing {@code wsse:BinarySecurityToken} for the same certificate (e.g. one
     * SoapUI's native Outgoing WSS already put there for its own Body/Timestamp signature) rather
     * than inserting a byte-identical duplicate, and returns its {@code wsu:Id}. Creates a new one
     * only if none matches.
     */
    private static String findOrCreateBst(Document doc, Element security, X509Certificate certificate)
            throws Exception {
        String certBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());

        NodeList children = security.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE
                    && "BinarySecurityToken".equals(node.getLocalName())
                    && SwaConstants.WSSE_NS.equals(node.getNamespaceURI())) {
                Element existingBst = (Element) node;
                String existingBase64 = existingBst.getTextContent().replaceAll("\\s+", "");
                if (certBase64.equals(existingBase64)) {
                    return getOrCreateWsuId(existingBst, "X509-");
                }
            }
        }

        String bstId = "X509-" + UUID.randomUUID();
        Element bst = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:BinarySecurityToken");
        bst.setAttribute("EncodingType", SwaConstants.BASE64_BINARY_ENCODING_TYPE);
        bst.setAttribute("ValueType", SwaConstants.X509_V3_VALUE_TYPE);
        bst.setAttributeNS(SwaConstants.WSU_NS, "wsu:Id", bstId);
        bst.setTextContent(certBase64);
        security.appendChild(bst);
        return bstId;
    }

    private static String getOrCreateWsuId(Element element, String idPrefix) {
        String id = element.getAttributeNS(SwaConstants.WSU_NS, "Id");
        if (id == null || id.isEmpty()) {
            id = idPrefix + UUID.randomUUID();
            element.setAttributeNS(SwaConstants.WSU_NS, "wsu:Id", id);
        }
        // Freshly parsed DOMs have no DTD/schema, so nothing marks wsu:Id as an XML ID attribute;
        // without this, the default same-document URIDereferencer cannot resolve "#..." references.
        element.setIdAttributeNS(SwaConstants.WSU_NS, "Id", true);
        return id;
    }

    private static Element getOrCreateTimestamp(Document doc, Element security) {
        Element timestamp = firstChildElementNS(security, SwaConstants.WSU_NS, "Timestamp");
        if (timestamp == null) {
            Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            Instant expires = now.plusSeconds(TIMESTAMP_TTL_SECONDS);

            timestamp = doc.createElementNS(SwaConstants.WSU_NS, "wsu:Timestamp");
            timestamp.setAttributeNS(SwaConstants.WSU_NS, "wsu:Id", "TS-" + UUID.randomUUID());

            Element created = doc.createElementNS(SwaConstants.WSU_NS, "wsu:Created");
            created.setTextContent(TIMESTAMP_FORMAT.format(now));
            timestamp.appendChild(created);

            Element expiresElement = doc.createElementNS(SwaConstants.WSU_NS, "wsu:Expires");
            expiresElement.setTextContent(TIMESTAMP_FORMAT.format(expires));
            timestamp.appendChild(expiresElement);

            security.insertBefore(timestamp, security.getFirstChild());
        }
        // See getOrCreateWsuId() - required even when reusing an existing Timestamp parsed fresh.
        timestamp.setIdAttributeNS(SwaConstants.WSU_NS, "Id", true);
        return timestamp;
    }

    private static Element firstChildElementNS(Element parent, String namespaceUri, String localName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE
                    && localName.equals(node.getLocalName())
                    && (namespaceUri == null ? node.getNamespaceURI() == null : namespaceUri.equals(node.getNamespaceURI()))) {
                return (Element) node;
            }
        }
        return null;
    }

    private static String qualify(Element sibling, String localName) {
        String prefix = sibling.getPrefix();
        return prefix == null || prefix.isEmpty() ? localName : prefix + ":" + localName;
    }
}
