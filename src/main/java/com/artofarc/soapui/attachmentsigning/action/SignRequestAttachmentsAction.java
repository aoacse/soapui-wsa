package com.artofarc.soapui.attachmentsigning.action;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.plugins.ActionConfiguration;
import com.eviware.soapui.support.UISupport;
import com.eviware.soapui.support.action.support.AbstractSoapUIAction;

/**
 * Adds a "Sign Attachments..." entry to the context menu of a plain interface-level Request node
 * (Interfaces &gt; Service &gt; Operation &gt; Request, i.e. one not wrapped in a TestCase step) -
 * SoapUI resolves that node's context menu via the action group named after its runtime class
 * ({@code WsdlRequest.class.getSimpleName() + "Actions"} = {@code WsdlRequestActions}), which is
 * a different group than the one used for SOAP Test Request steps inside a TestCase (see {@link
 * SignTestStepAttachmentsAction}).
 */
@ActionConfiguration(actionGroup = "WsdlRequestActions", targetType = WsdlRequest.class,
        description = "Signs one or more attachments of this request using WS-Security SwA (SOAP-with-Attachments)")
public class SignRequestAttachmentsAction extends AbstractSoapUIAction<WsdlRequest> {

    public SignRequestAttachmentsAction() {
        super("Sign Attachments...", "Signs attachments of this request using WS-Security SwA");
    }

    @Override
    public void perform(WsdlRequest request, Object param) {
        WsdlProject project = request.getOperation().getInterface().getProject();
        SigningConfigDialog dialog = new SigningConfigDialog(UISupport.getMainFrame(), project, request);
        dialog.setVisible(true);
    }
}
