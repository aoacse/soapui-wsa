package de.sensler.soapui.attachmentsigning.action;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.teststeps.WsdlTestRequest;
import com.eviware.soapui.impl.wsdl.teststeps.WsdlTestRequestStep;
import com.eviware.soapui.plugins.ActionConfiguration;
import com.eviware.soapui.support.UISupport;
import com.eviware.soapui.support.action.support.AbstractSoapUIAction;

/**
 * Adds a "Sign Attachments..." entry to the context menu / toolbar of SOAP Test Request steps,
 * opening {@link SigningConfigDialog} to configure and/or perform WS-Security SwA attachment
 * signing for that step's request.
 */
@ActionConfiguration(actionGroup = "WsdlTestStepActions", targetType = WsdlTestRequestStep.class,
        description = "Signs one or more attachments of this request using WS-Security SwA (SOAP-with-Attachments)")
public class SignAttachmentsAction extends AbstractSoapUIAction<WsdlTestRequestStep> {

    public SignAttachmentsAction() {
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
