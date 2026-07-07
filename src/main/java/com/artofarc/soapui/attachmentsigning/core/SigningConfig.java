package com.artofarc.soapui.attachmentsigning.core;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.model.propertyexpansion.DefaultPropertyExpansionContext;
import com.eviware.soapui.model.propertyexpansion.PropertyExpansionContext;

/**
 * Persists the attachment-signing configuration as custom properties on the {@link WsdlProject},
 * the same place SoapUI already keeps its WS-Security Keystores/Outgoing WSS configurations - so
 * one project-wide setup covers every request/TestStep in the project.
 *
 * <p>The password property supports SoapUI property expansion (e.g. {@code ${#Project#myPwd}}) so
 * it does not have to be stored in the project file in plain text.
 */
public final class SigningConfig {

    private static final String PREFIX = "AttachmentSigning.";

    public static final String CRYPTO = PREFIX + "crypto";
    public static final String ALIAS = PREFIX + "alias";
    public static final String PASSWORD = PREFIX + "password";
    public static final String TRANSFORM = PREFIX + "transform";
    public static final String AUTO_SIGN = PREFIX + "autoSign";
    public static final String INCLUDE_BODY_TIMESTAMP = PREFIX + "includeBodyAndTimestamp";

    private SigningConfig() {
    }

    public static String get(WsdlProject project, String key, String defaultValue) {
        if (project == null || !project.hasProperty(key)) {
            return defaultValue;
        }
        String value = project.getPropertyValue(key);
        return value == null ? defaultValue : value;
    }

    public static void set(WsdlProject project, String key, String value) {
        project.setPropertyValue(key, value == null ? "" : value);
    }

    public static boolean isAutoSignEnabled(WsdlProject project) {
        return Boolean.parseBoolean(get(project, AUTO_SIGN, "false"));
    }

    public static boolean isIncludeBodyAndTimestamp(WsdlProject project) {
        return Boolean.parseBoolean(get(project, INCLUDE_BODY_TIMESTAMP, "false"));
    }

    public static SwaTransformType getTransformType(WsdlProject project) {
        return SwaTransformType.fromName(get(project, TRANSFORM, null), SwaTransformType.CONTENT);
    }

    /** Expands property-expansion placeholders (e.g. {@code ${#Project#x}}) in the stored password. */
    public static String getExpandedPassword(WsdlProject project) {
        String password = get(project, PASSWORD, "");
        PropertyExpansionContext context = new DefaultPropertyExpansionContext(project);
        return context.expand(password);
    }
}
