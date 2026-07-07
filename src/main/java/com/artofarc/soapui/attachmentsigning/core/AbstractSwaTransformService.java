package com.artofarc.soapui.attachmentsigning.core;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Base for the two JSR 105 {@link TransformService} implementations for the WS-Security SwA
 * Profile 1.1 attachment transforms. Neither transform takes parameters, so only {@link
 * #toOctets(AttachmentData)} needs to be implemented by subclasses.
 */
public abstract class AbstractSwaTransformService extends TransformService {

    protected abstract byte[] toOctets(AttachmentData data) throws TransformException;

    @Override
    public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This transform does not take parameters");
        }
    }

    @Override
    public void init(XMLStructure parent, XMLCryptoContext context) {
        // no parameters to read from the (unmarshalled) Transform element
    }

    @Override
    public void marshalParams(XMLStructure parent, XMLCryptoContext context) {
        // no child parameters to write into the Transform element
    }

    @Override
    public AlgorithmParameterSpec getParameterSpec() {
        return null;
    }

    @Override
    public boolean isFeatureSupported(String feature) {
        return false;
    }

    @Override
    public Data transform(Data data, XMLCryptoContext context) throws TransformException {
        if (!(data instanceof AttachmentData)) {
            throw new TransformException("Expected the dereferenced data of a \"cid:\" URI, got " + data);
        }
        return new OctetStreamData(new ByteArrayInputStream(toOctets((AttachmentData) data)));
    }

    @Override
    public Data transform(Data data, XMLCryptoContext context, OutputStream os) throws TransformException {
        if (!(data instanceof AttachmentData)) {
            throw new TransformException("Expected the dereferenced data of a \"cid:\" URI, got " + data);
        }
        try {
            os.write(toOctets((AttachmentData) data));
        } catch (IOException e) {
            throw new TransformException(e.getMessage(), e);
        }
        return null;
    }
}
