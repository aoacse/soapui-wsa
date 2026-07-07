package de.sensler.soapui.attachmentsigning.core;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.support.wss.WssCrypto;
import com.eviware.soapui.model.iface.Attachment;
import com.eviware.soapui.support.xml.XmlUtils;
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
 * transform {@link SwaTransformType#getUri()}).
 *
 * <p>The private key and certificate are taken from one of the project's existing WS-Security
 * Keystores ({@link WssCrypto}), so key material is managed exactly the way SoapUI's built-in
 * "Outgoing WS-Security Configurations" already do.
 */
public final class AttachmentSigner {

    private AttachmentSigner() {
    }

    /**
     * Signs the given request's attachments in place and returns the resulting request XML; does
     * not itself call {@code request.setRequestContent(...)} so callers can decide how to handle
     * failures.
     *
     * @param contentIdsToSign Content-IDs (with or without angle brackets) of the attachments to
     *                          sign, or {@code null}/empty to sign every attachment on the request.
     */
    public static String sign(WsdlRequest request, WssCrypto wssCrypto, String alias, String password,
                               SwaTransformType transformType, Collection<String> contentIdsToSign) throws Exception {
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

        Document doc = XmlUtils.parseXml(request.getRequestContent());
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

        String bstId = "X509-" + UUID.randomUUID();
        Element bst = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:BinarySecurityToken");
        bst.setAttribute("EncodingType", SwaConstants.BASE64_BINARY_ENCODING_TYPE);
        bst.setAttribute("ValueType", SwaConstants.X509_V3_VALUE_TYPE);
        bst.setAttributeNS(SwaConstants.WSU_NS, "wsu:Id", bstId);
        bst.setTextContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        security.appendChild(bst);

        Element str = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:SecurityTokenReference");
        Element strRef = doc.createElementNS(SwaConstants.WSSE_NS, "wsse:Reference");
        strRef.setAttribute("URI", "#" + bstId);
        strRef.setAttribute("ValueType", SwaConstants.X509_V3_VALUE_TYPE);
        str.appendChild(strRef);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        DigestMethod digestMethod = fac.newDigestMethod(SwaConstants.DIGEST_SHA256, null);

        List<Reference> references = new ArrayList<>();
        for (String cid : idsToSign) {
            Transform transform = fac.newTransform(transformType.getUri(), (TransformParameterSpec) null);
            references.add(fac.newReference(AttachmentURIDereferencer.toCidUri(cid), digestMethod,
                    Collections.singletonList(transform), null, null));
        }

        CanonicalizationMethod c14n = fac.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = fac.newSignatureMethod(SwaConstants.SIGNATURE_RSA_SHA256, null);
        SignedInfo signedInfo = fac.newSignedInfo(c14n, signatureMethod, references);

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(new DOMStructure(str)));

        XMLSignature signature = fac.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext signContext = new DOMSignContext(privateKey, security);
        signContext.setURIDereferencer(new AttachmentURIDereferencer(byContentId));
        signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");
        signature.sign(signContext);

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
