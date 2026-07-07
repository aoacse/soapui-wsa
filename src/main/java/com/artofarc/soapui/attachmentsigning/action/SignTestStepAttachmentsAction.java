package com.artofarc.soapui.attachmentsigning.action;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.teststeps.WsdlTestRequest;
import com.eviware.soapui.impl.wsdl.teststeps.WsdlTestRequestStep;
import com.eviware.soapui.plugins.ActionConfiguration;
import com.eviware.soapui.support.UISupport;
import com.eviware.soapui.support.action.support.AbstractSoapUIAction;

/**
 * Adds a "Sign Attachments..." entry to the context menu of SOAP Test Request steps inside a
 * TestCase, opening {@link SigningConfigDialog} to configure and/or perform WS-Security SwA
 * attachment signing for that step's request.
 *
 * <p>Registered under the "WsdlTestStepActions" group, which every concrete TestStep type's own
 * action group (e.g. "WsdlTestRequestStepActions") merges in - see {@code
 * WsdlTestStepSoapUIActionGroup} in SoapUI core.
 */
@ActionConfiguration(actionGroup = "WsdlTestStepActions", targetType = WsdlTestRequestStep.class,
        description = "Signs one or more attachments of this request using WS-Security SwA (SOAP-with-Attachments)")
public class SignTestStepAttachmentsAction extends AbstractSoapUIAction<WsdlTestRequestStep> {

    public SignTestStepAttachmentsAction() {
        super("Sign Attachments...", "Signs attachments of this request using WS-Security SwA");
    }

    @Override
    public void perform(WsdlTestRequestStep testStep, Object param) {
        WsdlTestRequest request = testStep.getTestRequest();
        WsdlProject project = request.getOperation().getInterface().getProject();
        SigningConfigDialog dialog = new SigningConfigDialog(UISupport.getMainFrame(), project, request);
        dialog.setVisible(true);
    }
}
