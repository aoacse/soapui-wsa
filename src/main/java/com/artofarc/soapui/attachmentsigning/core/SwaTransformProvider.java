package com.artofarc.soapui.attachmentsigning.core;

import java.security.Provider;
import java.util.Collections;

/**
 * Registers {@link SwaContentTransformService} and {@link SwaCompleteTransformService} as JSR 105
 * ("DOM" mechanism) {@code TransformService} algorithms, so that {@code
 * XMLSignatureFactory.newTransform(uri, ...)} can create them by URI. Register once via {@link
 * #install()} before building any signature that uses these transforms.
 */
@SuppressWarnings("deprecation")
public final class SwaTransformProvider extends Provider {

    private static volatile boolean installed;

    public SwaTransformProvider() {
        super("SwaAttachmentTransforms", 1.0, "WS-Security SwA Profile 1.1 attachment signature transforms");
        putService(new Service(this, "TransformService", SwaConstants.ATTACHMENT_CONTENT_SIGNATURE_TRANSFORM,
                SwaContentTransformService.class.getName(), null, Collections.singletonMap("MechanismType", "DOM")));
        putService(new Service(this, "TransformService", SwaConstants.ATTACHMENT_COMPLETE_SIGNATURE_TRANSFORM,
                SwaCompleteTransformService.class.getName(), null, Collections.singletonMap("MechanismType", "DOM")));
    }

    /**
     * Idempotently registers this provider with the JVM's security provider list. Safe to call
     * repeatedly (e.g. from every signing operation).
     */
    public static void install() {
        if (!installed) {
            synchronized (SwaTransformProvider.class) {
                if (!installed) {
                    java.security.Security.addProvider(new SwaTransformProvider());
                    installed = true;
                }
            }
        }
    }
}
