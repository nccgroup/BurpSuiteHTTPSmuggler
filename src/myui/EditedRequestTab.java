/*
 * Burp Suite HTTP Smuggler
 * 
 * Released as open source by NCC Group - https://www.nccgroup.trust/
 * 
 * Developed by:
 *     Soroush Dalili (@irsdl)
 * 
 * Project link: https://github.com/nccgroup/BurpSuiteHTTPSmuggler/
 * 
 * Released under AGPL v3.0 see LICENSE for more information
 * 
 * */

package myui;

import java.awt.Component;
import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.ITextEditor;

// based on https://github.com/PortSwigger/example-custom-editor-tab/blob/master/java/BurpExtender.java
public class EditedRequestTab implements IMessageEditorTabFactory, IMessageEditorTab{
	private boolean editable;
    private ITextEditor txtInput;
    //private byte[] changedMessage;
    private byte[] originalMessage;
    private IBurpExtenderCallbacks _callbacks;
    
	public EditedRequestTab(IBurpExtenderCallbacks callbacks, boolean editable, byte[] changedMessage, byte[] originalMessage)
    {
        this._callbacks = callbacks;
		this.editable = editable;
		//this.changedMessage = changedMessage;
		this.originalMessage = originalMessage;
		
        txtInput = _callbacks.createTextEditor();
        txtInput.setEditable(editable);
        txtInput.setText(changedMessage);
        
    }
	
	@Override
	public String getTabCaption() {
		return "HTTP Smuggler Output";
	}

	@Override
	public Component getUiComponent() {
		return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		if(isRequest)
			return true;
		else
			return false;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		 if (content == null)
         {
             // clear our display
             txtInput.setText(null);
             txtInput.setEditable(false);
         }
         else
         {
             txtInput.setText(content);
             txtInput.setEditable(editable);
         }
         
         // remember the displayed content
         // currentMessage = content;
		
	}

	@Override
	public byte[] getMessage() {
		return originalMessage;
	}

	@Override
	public boolean isModified() {
		// not needed
		return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
		// not needed
		return txtInput.getSelectedText();
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		this.editable = editable;
		return this;
	}


}
