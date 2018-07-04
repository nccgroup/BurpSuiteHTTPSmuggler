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

package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import mutation.HTTPEncodingObject;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener
{

	private PrintWriter _stdout;
	private PrintWriter _stderr;
	private JTabbedPane _topTabs;
	private IBurpExtenderCallbacks _callbacks;
	private JTabbedPane topTabs;

	public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
	{
		_callbacks = callbacks;
		// obtain our output stream
		_stdout = new PrintWriter(_callbacks.getStdout(), true);
		_stderr = new PrintWriter(_callbacks.getStderr(), true);

		// set our extension name
		_callbacks.setExtensionName("HTTP Smuggler");

		// register ourselves as an HTTP listener
		callbacks.registerHttpListener(BurpExtender.this);

		// create our UI
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{
				topTabs = new JTabbedPane();

				topTabs.addTab("Scope", null, new myui.ScopeTab(callbacks, _stdout, _stderr), null);
				topTabs.addTab("Encoding", null, new myui.EncodingTab(callbacks, _stdout, _stderr), null);	
				topTabs.addTab("About", null, new myui.AboutTab(callbacks, _stdout, _stderr), null);	

				// customize our UI components
				callbacks.customizeUiComponent(topTabs); 
				helper.UIStuff.updateJCheckBoxBackground(topTabs);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});

	}

	@Override
	public String getTabCaption()
	{
		return "HTTP Smuggler Settings";
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {		
		if(messageIsRequest) {
			/* to calculate the scope, OR has not been implemented yet*/
			boolean isDisabled = false;
			boolean isInScope = false;
			boolean isTargetInScope = true;
			boolean isURLPathInScope = true;
			boolean isHeaderInScope = true;

			IRequestInfo analyzedReq = _callbacks.getHelpers().analyzeRequest(messageInfo);
			URL uUrl = analyzedReq.getUrl();
			/* find the right scope based on the settings*/
			int targetScopeOption =(int) loadExtensionSettingHelper("targetScopeOption","int",0);
			int pathRegExOption =(int) loadExtensionSettingHelper("pathRegExOption","int",0);
			String pathRegEx =(String) loadExtensionSettingHelper("pathRegEx","string","");
			int headerRegExOption =(int) loadExtensionSettingHelper("headerRegExOption","int",0);
			String headerRegEx =(String) loadExtensionSettingHelper("headerRegEx","string","");

			boolean chckbxAllTools =(boolean) loadExtensionSettingHelper("chckbxAllTools","bool",false);
			boolean chckbxProxy =(boolean) loadExtensionSettingHelper("chckbxProxy","bool",false);
			boolean chckbxScanner =(boolean) loadExtensionSettingHelper("chckbxScanner","bool",false);
			boolean chckbxIntruder =(boolean) loadExtensionSettingHelper("chckbxIntruder","bool",false);
			boolean chckbxRepeator =(boolean) loadExtensionSettingHelper("chckbxRepeator","bool",true);
			boolean chckbxExtender =(boolean) loadExtensionSettingHelper("chckbxExtender","bool",false);
			boolean chckbxTarget =(boolean) loadExtensionSettingHelper("chckbxTarget","bool",false);
			boolean chckbxSequencer =(boolean) loadExtensionSettingHelper("chckbxSequencer","bool",false);
			boolean chckbxSpider =(boolean) loadExtensionSettingHelper("chckbxSpider","bool",false);

			if(targetScopeOption==1 && pathRegExOption==1 && headerRegExOption==1) {
				//evrything is disabled
				isDisabled = true;
			}

			if(!isDisabled) {
				if(targetScopeOption < 1 && !_callbacks.isInScope(uUrl)) {
					isTargetInScope = false;
				}


				if(isTargetInScope && pathRegExOption < 1 && !pathRegEx.isEmpty()){
					// AND rule for path/url regex
					Pattern pathPattern = Pattern.compile(pathRegEx);
					Matcher matcher_pathURL = pathPattern.matcher(uUrl.toString());
					if (!matcher_pathURL.find())
					{
						isURLPathInScope = false;
					}
				}

				if(isTargetInScope && isURLPathInScope && headerRegExOption < 1 && !headerRegEx.isEmpty()){
					// AND rule for header regex
					Pattern headerPattern = Pattern.compile(headerRegEx);

					StringBuilder sb = new StringBuilder();
					for (String headerLine : analyzedReq.getHeaders())
					{
						sb.append(headerLine);
						sb.append("\r\n");
					}
					Matcher matcher_header = headerPattern.matcher(sb.toString());
					if (!matcher_header.find())
					{
						isHeaderInScope = false;
					}
				}



				if (isTargetInScope && isURLPathInScope && isHeaderInScope){
					// check the tool!
					if(chckbxAllTools){
						isInScope = true;
					}else if(chckbxProxy && toolFlag==_callbacks.TOOL_PROXY){
						isInScope = true;
					}else if(chckbxIntruder && toolFlag==_callbacks.TOOL_INTRUDER){
						isInScope = true;
					}else if(chckbxRepeator && toolFlag==_callbacks.TOOL_REPEATER){
						isInScope = true;
					}else if(chckbxScanner && toolFlag==_callbacks.TOOL_SCANNER){
						isInScope = true;
					}else if(chckbxSequencer && toolFlag==_callbacks.TOOL_SEQUENCER){
						isInScope = true;
					}else if(chckbxSpider && toolFlag==_callbacks.TOOL_SPIDER){
						isInScope = true;
					}else if(chckbxExtender && toolFlag==_callbacks.TOOL_EXTENDER){
						isInScope = true;
					}else if(chckbxTarget && toolFlag==_callbacks.TOOL_TARGET){
						isInScope = true;
					}
				}


				if (isInScope){
					//logIt(toolFlag, messageIsRequest, messageInfo, null);
					mutation.HttpEncoding httpEcnoding = new mutation.HttpEncoding(_callbacks,_stdout,_stderr,true);
					try {
						String newHTTPMessage = httpEcnoding.encodeHTTPMessage(messageInfo.getRequest(), loadHTTPEncodingObjectFromExtensionSetting());
						if(newHTTPMessage.isEmpty()) {
							_stdout.println("Message was not encoded - perhaps it was not eligible or there was an error (see the error tab)");
							_stdout.println("Enable the debug mode to see more details");
						}else {
							byte[] requestByte = newHTTPMessage.getBytes("ISO-8859-1");
							messageInfo.setRequest(requestByte);	
						}
					} catch (UnsupportedEncodingException e) {
						_stderr.println(e.getMessage());
					}
				}
			}
		}
	}

	@Override
	public Component getUiComponent() {
		return topTabs;
	}

	private Object loadExtensionSettingHelper(String name, String type, Object defaultValue) {
		Object value = null;
		try {
			String temp_value = _callbacks.loadExtensionSetting(name);
			if(temp_value!=null && !temp_value.equals("")) {
				switch(type.toLowerCase()){
				case "int":
				case "integer":
					value = Integer.valueOf(temp_value);
					break;
				case "bool":
				case "boolean":
					value = Boolean.valueOf(temp_value);
					break;
				default:
					value = temp_value;
					break;
				}
			}
		}catch(Exception e) {
			_stderr.println(e.getMessage());
		}

		if(value==null) {
			value = defaultValue;
		}
		return value;
	}
	
	private HTTPEncodingObject loadHTTPEncodingObjectFromExtensionSetting() {
		HTTPEncodingObject currentHTTPEncodingObject = new HTTPEncodingObject();
		currentHTTPEncodingObject.setPreventReEncoding((boolean) loadExtensionSettingHelper("preventReEncoding", "bool", true));
		currentHTTPEncodingObject.setEncodeMicrosoftURLEncode((boolean) loadExtensionSettingHelper("encodeMicrosoftURLEncode", "bool", false));
		currentHTTPEncodingObject.setEncodeDespiteErrors((boolean) loadExtensionSettingHelper("encodeDespiteErrors", "bool", false));
		currentHTTPEncodingObject.setAddACharToEmptyBody((boolean) loadExtensionSettingHelper("addACharToEmptyBody", "bool", true));
		currentHTTPEncodingObject.setReplaceGETwithPOST((boolean) loadExtensionSettingHelper("replaceGETwithPOST", "bool", false));
		currentHTTPEncodingObject.setEncodable_QS((boolean) loadExtensionSettingHelper("isEncodable_QS", "bool", true));
		currentHTTPEncodingObject.setEncodable_body((boolean) loadExtensionSettingHelper("isEncodable_body", "bool", true));
		currentHTTPEncodingObject.setEncodable_QS_delimiter((boolean) loadExtensionSettingHelper("isEncodable_QS_delimiter", "bool", false));
		currentHTTPEncodingObject.setEncodable_urlencoded_body_delimiter((boolean) loadExtensionSettingHelper("isEncodable_urlencoded_body_delimiter", "bool", false));
		currentHTTPEncodingObject.setEncodable_QS_equal_sign((boolean) loadExtensionSettingHelper("isEncodable_QS_equal_sign", "bool", false));
		currentHTTPEncodingObject.setEncodable_urlencoded_body_equal_sign((boolean) loadExtensionSettingHelper("isEncodable_urlencoded_body_equal_sign", "bool", false));
		currentHTTPEncodingObject.setURLEncoded_incoming_QS((boolean) loadExtensionSettingHelper("isURLEncoded_incoming_QS", "bool", true));
		currentHTTPEncodingObject.setURLEncoded_incoming_body((boolean) loadExtensionSettingHelper("isURLEncoded_incoming_body", "bool", true));
		currentHTTPEncodingObject.setURLEncoded_outgoing_QS((boolean) loadExtensionSettingHelper("isURLEncoded_outgoing_QS", "bool", true));
		currentHTTPEncodingObject.setURLEncoded_outgoing_body((boolean) loadExtensionSettingHelper("isURLEncoded_outgoing_body", "bool", true));
		currentHTTPEncodingObject.setAllChar_URLEncoded_outgoing_QS((boolean) loadExtensionSettingHelper("isAllChar_URLEncoded_outgoing_QS", "bool", true));
		currentHTTPEncodingObject.setAllChar_URLEncoded_outgoing_body((boolean) loadExtensionSettingHelper("isAllChar_URLEncoded_outgoing_body", "bool", true));
		currentHTTPEncodingObject.setTrimSpacesInContentTypeHeaderValues((boolean) loadExtensionSettingHelper("trimSpacesInContentTypeHeaderValues", "bool", true));
		currentHTTPEncodingObject.setEncodeNameValueOnlyMultipart((boolean) loadExtensionSettingHelper("encodeNameValueOnlyMultipart", "bool", false));
		currentHTTPEncodingObject.setUse_incoming_charset_for_request_encoding((boolean) loadExtensionSettingHelper("use_incoming_charset_for_request_encoding", "bool", true));
		
		currentHTTPEncodingObject.setDelimiter_QS((String) loadExtensionSettingHelper("delimiter_QS", "string", "?"));
		currentHTTPEncodingObject.setDelimiter_QS_param((String) loadExtensionSettingHelper("delimiter_QS_param", "string", "&"));
		currentHTTPEncodingObject.setQS_equalSign((String) loadExtensionSettingHelper("QS_equalSign", "string", "="));
		currentHTTPEncodingObject.setDelimiter_urlencoded_body_param((String) loadExtensionSettingHelper("delimiter_urlencoded_body_param", "string", "&"));
		currentHTTPEncodingObject.setBody_param_equalSign((String) loadExtensionSettingHelper("body_param_equalSign", "string", "="));
		currentHTTPEncodingObject.setOutgoing_request_encoding((String) loadExtensionSettingHelper("outgoing_request_encoding", "string", "ibm500"));
		currentHTTPEncodingObject.setIncoming_request_encoding((String) loadExtensionSettingHelper("incoming_request_encoding", "string", "utf-8"));
		
		return currentHTTPEncodingObject;
	}

}