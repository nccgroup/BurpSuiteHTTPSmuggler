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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.io.PrintWriter;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import mutation.HTTPEncodingObject;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.JTextField;

public class EncodingTab extends JScrollPane {
	private IBurpExtenderCallbacks _callbacks;;
	private IExtensionHelpers _helpers;
	private PrintWriter _stdout;
	private PrintWriter _stderr;
	
	private enum policyOptions{
		aspx("ASPX/IIS"),
		jsp("JSP/TOMCAT"),
		py2("Py2/Django"),
		py3("Py3/Django"),
		custom("custom");
		private String value;
		   private policyOptions(String value)
		   {
		      this.value = value;
		   }

		   public String toString()
		   {
		      return this.value; //This will return , # or +
		   }
	}
	private JComboBox comboBoxPolicy = new JComboBox(new DefaultComboBoxModel(policyOptions.values()));
	private JTextField delimiter_QS;
	private JTextField delimiter_QS_param;
	private JTextField QS_equalSign;
	private JTextField delimiter_urlencoded_body_param;
	private JTextField body_param_equalSign;
	private JTextField outgoing_request_encoding;
	private JTextField incoming_request_encoding;
	JCheckBox preventReEncoding = new JCheckBox("Prevent re-encoding");

	JCheckBox encodeMicrosoftURLEncode = new JCheckBox("Encode using MS URLEncode");
	JCheckBox encodeDespiteErrors = new JCheckBox("Encode despite errors");
	JCheckBox addACharToEmptyBody = new JCheckBox("Add a character to an empty body");
	JCheckBox replaceGETwithPOST = new JCheckBox("Replace GET with POST");
	JCheckBox isEncodable_QS = new JCheckBox("Encode querystring?");
	JCheckBox isEncodable_body = new JCheckBox("Encode body?");
	JCheckBox isEncodable_QS_delimiter = new JCheckBox("Encode querystring delimiter?");
	JCheckBox isEncodable_urlencoded_body_delimiter = new JCheckBox("Encode URL-encoded body delimiter?");
	JCheckBox isEncodable_QS_equal_sign = new JCheckBox("Encode equal sign in querystring?");
	JCheckBox isEncodable_urlencoded_body_equal_sign = new JCheckBox("Encode equal sign in URL-encoded body?");
	JCheckBox isURLEncoded_incoming_QS = new JCheckBox("Is incoming querystring URL-encoded?");
	JCheckBox isURLEncoded_incoming_body = new JCheckBox("Is incoming body URL-encoded?");
	JCheckBox isURLEncoded_outgoing_QS = new JCheckBox("Is outgoing querystring URL-encoded?");
	JCheckBox isURLEncoded_outgoing_body = new JCheckBox("Is outgoing body URL-encoded?");
	JCheckBox isAllChar_URLEncoded_outgoing_QS = new JCheckBox("URL-encoding all characters in querystring?");
	JCheckBox isAllChar_URLEncoded_outgoing_body = new JCheckBox("URL-encoding all characters in POST body");
	JCheckBox trimSpacesInContentTypeHeaderValues = new JCheckBox("Trim spaces from content-type parts");
	JCheckBox encodeNameValueOnlyMultipart = new JCheckBox("Encode name value only in multipart");
	JCheckBox use_incoming_charset_for_request_encoding = new JCheckBox("Use incoming charset for encoding");

	/**
	 * Create the panel.
	 */
	public EncodingTab(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
		_callbacks = callbacks;
		_helpers = _callbacks.getHelpers();
		_stdout = stdout;
		_stderr = stderr;
		

		JPanel panel = new JPanel();
		setViewportView(panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 1.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JLabel lblPolicy = new JLabel("Policy:");
		GridBagConstraints gbc_lblPolicy = new GridBagConstraints();
		gbc_lblPolicy.insets = new Insets(0, 0, 5, 5);
		gbc_lblPolicy.anchor = GridBagConstraints.EAST;
		gbc_lblPolicy.gridx = 1;
		gbc_lblPolicy.gridy = 0;
		panel.add(lblPolicy, gbc_lblPolicy);
		
		GridBagConstraints gbc_comboBoxPolicy = new GridBagConstraints();
		gbc_comboBoxPolicy.insets = new Insets(0, 0, 5, 5);
		gbc_comboBoxPolicy.anchor = GridBagConstraints.WEST;
		gbc_comboBoxPolicy.gridx = 2;
		gbc_comboBoxPolicy.gridy = 0;
		panel.add(comboBoxPolicy, gbc_comboBoxPolicy);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(null, "Options", TitledBorder.LEFT, TitledBorder.TOP, null, null));
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.insets = new Insets(0, 0, 5, 5);
		gbc_panel_1.fill = GridBagConstraints.BOTH;
		gbc_panel_1.gridx = 2;
		gbc_panel_1.gridy = 1;
		panel.add(panel_1, gbc_panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{0, 0, 0, 0};
		gbl_panel_1.rowHeights = new int[]{35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35, 35};
		gbl_panel_1.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		
		preventReEncoding.setToolTipText("Only encodes when there is no charset or it is one of these: \"UTF-8\", \"UTF-16\", \"UTF-32\", \"ISO-8859-1\"");
		GridBagConstraints gbc_preventReEncoding = new GridBagConstraints();
		gbc_preventReEncoding.anchor = GridBagConstraints.WEST;
		gbc_preventReEncoding.insets = new Insets(0, 0, 5, 5);
		gbc_preventReEncoding.gridx = 0;
		gbc_preventReEncoding.gridy = 0;
		panel_1.add(preventReEncoding, gbc_preventReEncoding);
		
		JLabel lblQuerystringDelimiter = new JLabel("Querystring url delimiter:");
		GridBagConstraints gbc_lblQuerystringDelimiter = new GridBagConstraints();
		gbc_lblQuerystringDelimiter.anchor = GridBagConstraints.EAST;
		gbc_lblQuerystringDelimiter.insets = new Insets(0, 0, 5, 5);
		gbc_lblQuerystringDelimiter.gridx = 1;
		gbc_lblQuerystringDelimiter.gridy = 0;
		panel_1.add(lblQuerystringDelimiter, gbc_lblQuerystringDelimiter);
		
		delimiter_QS = new JTextField();
		delimiter_QS.setText("?");
		GridBagConstraints gbc_delimiter_QS = new GridBagConstraints();
		gbc_delimiter_QS.anchor = GridBagConstraints.WEST;
		gbc_delimiter_QS.insets = new Insets(0, 0, 5, 0);
		gbc_delimiter_QS.gridx = 2;
		gbc_delimiter_QS.gridy = 0;
		panel_1.add(delimiter_QS, gbc_delimiter_QS);
		delimiter_QS.setColumns(10);
		
		encodeMicrosoftURLEncode.setToolTipText("to encode utf-8 characters to their %uXXXX format");
		GridBagConstraints gbc_encodeMicrosoftURLEncode = new GridBagConstraints();
		gbc_encodeMicrosoftURLEncode.insets = new Insets(0, 0, 5, 5);
		gbc_encodeMicrosoftURLEncode.anchor = GridBagConstraints.WEST;
		gbc_encodeMicrosoftURLEncode.gridx = 0;
		gbc_encodeMicrosoftURLEncode.gridy = 1;
		panel_1.add(encodeMicrosoftURLEncode, gbc_encodeMicrosoftURLEncode);
		
		JLabel lblQuerystringParameterDelimiter = new JLabel("Querystring parameter delimiter:");
		GridBagConstraints gbc_lblQuerystringParameterDelimiter = new GridBagConstraints();
		gbc_lblQuerystringParameterDelimiter.anchor = GridBagConstraints.EAST;
		gbc_lblQuerystringParameterDelimiter.insets = new Insets(0, 0, 5, 5);
		gbc_lblQuerystringParameterDelimiter.gridx = 1;
		gbc_lblQuerystringParameterDelimiter.gridy = 1;
		panel_1.add(lblQuerystringParameterDelimiter, gbc_lblQuerystringParameterDelimiter);
		
		delimiter_QS_param = new JTextField();
		delimiter_QS_param.setText("&");
		GridBagConstraints gbc_delimiter_QS_param = new GridBagConstraints();
		gbc_delimiter_QS_param.anchor = GridBagConstraints.WEST;
		gbc_delimiter_QS_param.insets = new Insets(0, 0, 5, 0);
		gbc_delimiter_QS_param.gridx = 2;
		gbc_delimiter_QS_param.gridy = 1;
		panel_1.add(delimiter_QS_param, gbc_delimiter_QS_param);
		delimiter_QS_param.setColumns(10);
		
		encodeDespiteErrors.setToolTipText("Can be dangerous as it can change all the parameters wrongly. This will be ignored if encodeMicrosoftURLEncode=true");
		GridBagConstraints gbc_encodeDespiteErrors = new GridBagConstraints();
		gbc_encodeDespiteErrors.insets = new Insets(0, 0, 5, 5);
		gbc_encodeDespiteErrors.anchor = GridBagConstraints.WEST;
		gbc_encodeDespiteErrors.gridx = 0;
		gbc_encodeDespiteErrors.gridy = 2;
		panel_1.add(encodeDespiteErrors, gbc_encodeDespiteErrors);
		
		JLabel lblQuerystringEqualSign = new JLabel("Querystring equal sign:");
		GridBagConstraints gbc_lblQuerystringEqualSign = new GridBagConstraints();
		gbc_lblQuerystringEqualSign.anchor = GridBagConstraints.EAST;
		gbc_lblQuerystringEqualSign.insets = new Insets(0, 0, 5, 5);
		gbc_lblQuerystringEqualSign.gridx = 1;
		gbc_lblQuerystringEqualSign.gridy = 2;
		panel_1.add(lblQuerystringEqualSign, gbc_lblQuerystringEqualSign);
		
		QS_equalSign = new JTextField();
		QS_equalSign.setText("=");
		GridBagConstraints gbc_QS_equalSign = new GridBagConstraints();
		gbc_QS_equalSign.insets = new Insets(0, 0, 5, 0);
		gbc_QS_equalSign.fill = GridBagConstraints.HORIZONTAL;
		gbc_QS_equalSign.gridx = 2;
		gbc_QS_equalSign.gridy = 2;
		panel_1.add(QS_equalSign, gbc_QS_equalSign);
		QS_equalSign.setColumns(10);
		
		GridBagConstraints gbc_addACharToEmptyBody = new GridBagConstraints();
		gbc_addACharToEmptyBody.anchor = GridBagConstraints.WEST;
		gbc_addACharToEmptyBody.insets = new Insets(0, 0, 5, 5);
		gbc_addACharToEmptyBody.gridx = 0;
		gbc_addACharToEmptyBody.gridy = 3;
		panel_1.add(addACharToEmptyBody, gbc_addACharToEmptyBody);
		
		JLabel lblUrlencodedBodyParameter = new JLabel("URL-encoded body parameter delimiter:");
		GridBagConstraints gbc_lblUrlencodedBodyParameter = new GridBagConstraints();
		gbc_lblUrlencodedBodyParameter.anchor = GridBagConstraints.EAST;
		gbc_lblUrlencodedBodyParameter.insets = new Insets(0, 0, 5, 5);
		gbc_lblUrlencodedBodyParameter.gridx = 1;
		gbc_lblUrlencodedBodyParameter.gridy = 3;
		panel_1.add(lblUrlencodedBodyParameter, gbc_lblUrlencodedBodyParameter);
		
		delimiter_urlencoded_body_param = new JTextField();
		delimiter_urlencoded_body_param.setText("&");
		GridBagConstraints gbc_delimiter_urlencoded_body_param = new GridBagConstraints();
		gbc_delimiter_urlencoded_body_param.insets = new Insets(0, 0, 5, 0);
		gbc_delimiter_urlencoded_body_param.fill = GridBagConstraints.HORIZONTAL;
		gbc_delimiter_urlencoded_body_param.gridx = 2;
		gbc_delimiter_urlencoded_body_param.gridy = 3;
		panel_1.add(delimiter_urlencoded_body_param, gbc_delimiter_urlencoded_body_param);
		delimiter_urlencoded_body_param.setColumns(10);
		
		GridBagConstraints gbc_replaceGETwithPOST = new GridBagConstraints();
		gbc_replaceGETwithPOST.insets = new Insets(0, 0, 5, 5);
		gbc_replaceGETwithPOST.anchor = GridBagConstraints.WEST;
		gbc_replaceGETwithPOST.gridx = 0;
		gbc_replaceGETwithPOST.gridy = 4;
		panel_1.add(replaceGETwithPOST, gbc_replaceGETwithPOST);
		
		JLabel lblBodyParameterEqual = new JLabel("Body parameter equal sign:");
		GridBagConstraints gbc_lblBodyParameterEqual = new GridBagConstraints();
		gbc_lblBodyParameterEqual.anchor = GridBagConstraints.EAST;
		gbc_lblBodyParameterEqual.insets = new Insets(0, 0, 5, 5);
		gbc_lblBodyParameterEqual.gridx = 1;
		gbc_lblBodyParameterEqual.gridy = 4;
		panel_1.add(lblBodyParameterEqual, gbc_lblBodyParameterEqual);
		
		body_param_equalSign = new JTextField();
		body_param_equalSign.setText("=");
		GridBagConstraints gbc_body_param_equalSign = new GridBagConstraints();
		gbc_body_param_equalSign.insets = new Insets(0, 0, 5, 0);
		gbc_body_param_equalSign.fill = GridBagConstraints.HORIZONTAL;
		gbc_body_param_equalSign.gridx = 2;
		gbc_body_param_equalSign.gridy = 4;
		panel_1.add(body_param_equalSign, gbc_body_param_equalSign);
		body_param_equalSign.setColumns(10);
		
		GridBagConstraints gbc_isEncodable_QS = new GridBagConstraints();
		gbc_isEncodable_QS.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_QS.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_QS.gridx = 0;
		gbc_isEncodable_QS.gridy = 5;
		panel_1.add(isEncodable_QS, gbc_isEncodable_QS);
		
		JLabel lblOutgoingRequestEncoding = new JLabel("Outgoing request encoding:");
		GridBagConstraints gbc_lblOutgoingRequestEncoding = new GridBagConstraints();
		gbc_lblOutgoingRequestEncoding.anchor = GridBagConstraints.EAST;
		gbc_lblOutgoingRequestEncoding.insets = new Insets(0, 0, 5, 5);
		gbc_lblOutgoingRequestEncoding.gridx = 1;
		gbc_lblOutgoingRequestEncoding.gridy = 5;
		panel_1.add(lblOutgoingRequestEncoding, gbc_lblOutgoingRequestEncoding);
		
		outgoing_request_encoding = new JTextField();
		outgoing_request_encoding.setText("ibm500");
		GridBagConstraints gbc_outgoing_request_encoding = new GridBagConstraints();
		gbc_outgoing_request_encoding.insets = new Insets(0, 0, 5, 0);
		gbc_outgoing_request_encoding.fill = GridBagConstraints.HORIZONTAL;
		gbc_outgoing_request_encoding.gridx = 2;
		gbc_outgoing_request_encoding.gridy = 5;
		panel_1.add(outgoing_request_encoding, gbc_outgoing_request_encoding);
		outgoing_request_encoding.setColumns(10);
		
		GridBagConstraints gbc_isEncodable_body = new GridBagConstraints();
		gbc_isEncodable_body.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_body.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_body.gridx = 0;
		gbc_isEncodable_body.gridy = 6;
		panel_1.add(isEncodable_body, gbc_isEncodable_body);
		
		JLabel lblDefaultIncomingRequest = new JLabel("Default incoming request encoding:");
		GridBagConstraints gbc_lblDefaultIncomingRequest = new GridBagConstraints();
		gbc_lblDefaultIncomingRequest.anchor = GridBagConstraints.EAST;
		gbc_lblDefaultIncomingRequest.insets = new Insets(0, 0, 5, 5);
		gbc_lblDefaultIncomingRequest.gridx = 1;
		gbc_lblDefaultIncomingRequest.gridy = 6;
		panel_1.add(lblDefaultIncomingRequest, gbc_lblDefaultIncomingRequest);
		
		incoming_request_encoding = new JTextField();
		incoming_request_encoding.setText("utf-8");
		GridBagConstraints gbc_incoming_request_encoding = new GridBagConstraints();
		gbc_incoming_request_encoding.insets = new Insets(0, 0, 5, 0);
		gbc_incoming_request_encoding.fill = GridBagConstraints.HORIZONTAL;
		gbc_incoming_request_encoding.gridx = 2;
		gbc_incoming_request_encoding.gridy = 6;
		panel_1.add(incoming_request_encoding, gbc_incoming_request_encoding);
		incoming_request_encoding.setColumns(10);
		
		GridBagConstraints gbc_isEncodable_QS_delimiter = new GridBagConstraints();
		gbc_isEncodable_QS_delimiter.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_QS_delimiter.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_QS_delimiter.gridx = 0;
		gbc_isEncodable_QS_delimiter.gridy = 7;
		panel_1.add(isEncodable_QS_delimiter, gbc_isEncodable_QS_delimiter);
		
		GridBagConstraints gbc_isEncodable_urlencoded_body_delimiter = new GridBagConstraints();
		gbc_isEncodable_urlencoded_body_delimiter.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_urlencoded_body_delimiter.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_urlencoded_body_delimiter.gridx = 0;
		gbc_isEncodable_urlencoded_body_delimiter.gridy = 8;
		panel_1.add(isEncodable_urlencoded_body_delimiter, gbc_isEncodable_urlencoded_body_delimiter);
		
		GridBagConstraints gbc_isEncodable_QS_equal_sign = new GridBagConstraints();
		gbc_isEncodable_QS_equal_sign.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_QS_equal_sign.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_QS_equal_sign.gridx = 0;
		gbc_isEncodable_QS_equal_sign.gridy = 9;
		panel_1.add(isEncodable_QS_equal_sign, gbc_isEncodable_QS_equal_sign);
		
		GridBagConstraints gbc_isEncodable_urlencoded_body_equal_sign = new GridBagConstraints();
		gbc_isEncodable_urlencoded_body_equal_sign.anchor = GridBagConstraints.WEST;
		gbc_isEncodable_urlencoded_body_equal_sign.insets = new Insets(0, 0, 5, 5);
		gbc_isEncodable_urlencoded_body_equal_sign.gridx = 0;
		gbc_isEncodable_urlencoded_body_equal_sign.gridy = 10;
		panel_1.add(isEncodable_urlencoded_body_equal_sign, gbc_isEncodable_urlencoded_body_equal_sign);
		
		GridBagConstraints gbc_isURLEncoded_incoming_QS = new GridBagConstraints();
		gbc_isURLEncoded_incoming_QS.anchor = GridBagConstraints.WEST;
		gbc_isURLEncoded_incoming_QS.insets = new Insets(0, 0, 5, 5);
		gbc_isURLEncoded_incoming_QS.gridx = 0;
		gbc_isURLEncoded_incoming_QS.gridy = 11;
		panel_1.add(isURLEncoded_incoming_QS, gbc_isURLEncoded_incoming_QS);
		
		isURLEncoded_incoming_body.setToolTipText("this is not active when it is a multipart message");
		GridBagConstraints gbc_isURLEncoded_incoming_body = new GridBagConstraints();
		gbc_isURLEncoded_incoming_body.anchor = GridBagConstraints.WEST;
		gbc_isURLEncoded_incoming_body.insets = new Insets(0, 0, 5, 5);
		gbc_isURLEncoded_incoming_body.gridx = 0;
		gbc_isURLEncoded_incoming_body.gridy = 12;
		panel_1.add(isURLEncoded_incoming_body, gbc_isURLEncoded_incoming_body);
		
		GridBagConstraints gbc_isURLEncoded_outgoing_QS = new GridBagConstraints();
		gbc_isURLEncoded_outgoing_QS.anchor = GridBagConstraints.WEST;
		gbc_isURLEncoded_outgoing_QS.insets = new Insets(0, 0, 5, 5);
		gbc_isURLEncoded_outgoing_QS.gridx = 0;
		gbc_isURLEncoded_outgoing_QS.gridy = 13;
		panel_1.add(isURLEncoded_outgoing_QS, gbc_isURLEncoded_outgoing_QS);
		
		isURLEncoded_outgoing_body.setToolTipText("this is not active when it is a multipart message");
		GridBagConstraints gbc_isURLEncoded_outgoing_body = new GridBagConstraints();
		gbc_isURLEncoded_outgoing_body.anchor = GridBagConstraints.WEST;
		gbc_isURLEncoded_outgoing_body.insets = new Insets(0, 0, 5, 5);
		gbc_isURLEncoded_outgoing_body.gridx = 0;
		gbc_isURLEncoded_outgoing_body.gridy = 14;
		panel_1.add(isURLEncoded_outgoing_body, gbc_isURLEncoded_outgoing_body);
		
		isAllChar_URLEncoded_outgoing_QS.setToolTipText("only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters");
		GridBagConstraints gbc_isAllChar_URLEncoded_outgoing_QS = new GridBagConstraints();
		gbc_isAllChar_URLEncoded_outgoing_QS.anchor = GridBagConstraints.WEST;
		gbc_isAllChar_URLEncoded_outgoing_QS.insets = new Insets(0, 0, 5, 5);
		gbc_isAllChar_URLEncoded_outgoing_QS.gridx = 0;
		gbc_isAllChar_URLEncoded_outgoing_QS.gridy = 15;
		panel_1.add(isAllChar_URLEncoded_outgoing_QS, gbc_isAllChar_URLEncoded_outgoing_QS);
		
		isAllChar_URLEncoded_outgoing_body.setToolTipText("only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters");
		GridBagConstraints gbc_isAllChar_URLEncoded_outgoing_body = new GridBagConstraints();
		gbc_isAllChar_URLEncoded_outgoing_body.anchor = GridBagConstraints.WEST;
		gbc_isAllChar_URLEncoded_outgoing_body.insets = new Insets(0, 0, 5, 5);
		gbc_isAllChar_URLEncoded_outgoing_body.gridx = 0;
		gbc_isAllChar_URLEncoded_outgoing_body.gridy = 16;
		panel_1.add(isAllChar_URLEncoded_outgoing_body, gbc_isAllChar_URLEncoded_outgoing_body);
		
		GridBagConstraints gbc_trimSpacesInContentTypeHeaderValues = new GridBagConstraints();
		gbc_trimSpacesInContentTypeHeaderValues.anchor = GridBagConstraints.WEST;
		gbc_trimSpacesInContentTypeHeaderValues.insets = new Insets(0, 0, 5, 5);
		gbc_trimSpacesInContentTypeHeaderValues.gridx = 0;
		gbc_trimSpacesInContentTypeHeaderValues.gridy = 17;
		panel_1.add(trimSpacesInContentTypeHeaderValues, gbc_trimSpacesInContentTypeHeaderValues);
		
		encodeNameValueOnlyMultipart.setToolTipText("python django needs this, IIS does not!");
		GridBagConstraints gbc_encodeNameValueOnlyMultipart = new GridBagConstraints();
		gbc_encodeNameValueOnlyMultipart.anchor = GridBagConstraints.WEST;
		gbc_encodeNameValueOnlyMultipart.insets = new Insets(0, 0, 5, 5);
		gbc_encodeNameValueOnlyMultipart.gridx = 0;
		gbc_encodeNameValueOnlyMultipart.gridy = 18;
		panel_1.add(encodeNameValueOnlyMultipart, gbc_encodeNameValueOnlyMultipart);
		
		GridBagConstraints gbc_use_incoming_charset_for_request_encoding = new GridBagConstraints();
		gbc_use_incoming_charset_for_request_encoding.anchor = GridBagConstraints.WEST;
		gbc_use_incoming_charset_for_request_encoding.insets = new Insets(0, 0, 0, 5);
		gbc_use_incoming_charset_for_request_encoding.gridx = 0;
		gbc_use_incoming_charset_for_request_encoding.gridy = 19;
		panel_1.add(use_incoming_charset_for_request_encoding, gbc_use_incoming_charset_for_request_encoding);
     
		init();
	}
	private void init(){
		//resetSettings();
		loadSettings();
		updateUIState();
		setActions();
		saveSettings(); 
	}

	private void updateUIState() {
		
		Object policy = comboBoxPolicy.getSelectedItem();

		if(!policy.equals(policyOptions.custom)) {
			HTTPEncodingObject newHTTPEncodingObject = new HTTPEncodingObject(policy.toString());
			preventReEncoding.setSelected(newHTTPEncodingObject.isPreventReEncoding());
			encodeMicrosoftURLEncode.setSelected(newHTTPEncodingObject.isEncodeMicrosoftURLEncode());
			encodeDespiteErrors.setSelected(newHTTPEncodingObject.isEncodeDespiteErrors());
			addACharToEmptyBody.setSelected(newHTTPEncodingObject.isAddACharToEmptyBody());
			replaceGETwithPOST.setSelected(newHTTPEncodingObject.isReplaceGETwithPOST());
			isEncodable_QS.setSelected(newHTTPEncodingObject.isEncodable_QS());
			isEncodable_body.setSelected(newHTTPEncodingObject.isEncodable_body());
			isEncodable_QS_delimiter.setSelected(newHTTPEncodingObject.isEncodable_QS_delimiter());
			isEncodable_urlencoded_body_delimiter.setSelected(newHTTPEncodingObject.isEncodable_urlencoded_body_delimiter());
			isEncodable_QS_equal_sign.setSelected(newHTTPEncodingObject.isEncodable_QS_equal_sign());
			isEncodable_urlencoded_body_equal_sign.setSelected(newHTTPEncodingObject.isEncodable_urlencoded_body_equal_sign());
			isURLEncoded_incoming_QS.setSelected(newHTTPEncodingObject.isURLEncoded_incoming_QS());
			isURLEncoded_incoming_body.setSelected(newHTTPEncodingObject.isURLEncoded_incoming_body());
			isURLEncoded_outgoing_QS.setSelected(newHTTPEncodingObject.isURLEncoded_outgoing_QS());
			isURLEncoded_outgoing_body.setSelected(newHTTPEncodingObject.isURLEncoded_outgoing_body());
			isAllChar_URLEncoded_outgoing_QS.setSelected(newHTTPEncodingObject.isAllChar_URLEncoded_outgoing_QS());
			isAllChar_URLEncoded_outgoing_body.setSelected(newHTTPEncodingObject.isAllChar_URLEncoded_outgoing_body());
			trimSpacesInContentTypeHeaderValues.setSelected(newHTTPEncodingObject.isTrimSpacesInContentTypeHeaderValues());
			encodeNameValueOnlyMultipart.setSelected(newHTTPEncodingObject.isEncodeNameValueOnlyMultipart());
			use_incoming_charset_for_request_encoding.setSelected(newHTTPEncodingObject.isUse_incoming_charset_for_request_encoding());
			
			delimiter_QS.setText(newHTTPEncodingObject.getDelimiter_QS());
			delimiter_QS_param.setText(newHTTPEncodingObject.getDelimiter_QS_param());
			QS_equalSign.setText(newHTTPEncodingObject.getQS_equalSign());
			delimiter_urlencoded_body_param.setText(newHTTPEncodingObject.getDelimiter_urlencoded_body_param());
			body_param_equalSign.setText(newHTTPEncodingObject.getBody_param_equalSign());
			outgoing_request_encoding.setText(newHTTPEncodingObject.getOutgoing_request_encoding());
			incoming_request_encoding.setText(newHTTPEncodingObject.getIncoming_request_encoding());
			
			comboBoxPolicy.setSelectedItem(policy);
		}
		
		
	}
	
	
	private void setActions() {
		setActionsJComboBoxHelper(comboBoxPolicy);
		
		setActionsJCheckBoxHelper(preventReEncoding);
		setActionsJCheckBoxHelper(encodeMicrosoftURLEncode);
		setActionsJCheckBoxHelper(encodeDespiteErrors);
		setActionsJCheckBoxHelper(addACharToEmptyBody);
		setActionsJCheckBoxHelper(replaceGETwithPOST);
		setActionsJCheckBoxHelper(isEncodable_QS);
		setActionsJCheckBoxHelper(isEncodable_body);
		setActionsJCheckBoxHelper(isEncodable_QS_delimiter);
		setActionsJCheckBoxHelper(isEncodable_urlencoded_body_delimiter);
		setActionsJCheckBoxHelper(isEncodable_QS_equal_sign);
		setActionsJCheckBoxHelper(isEncodable_urlencoded_body_equal_sign);
		setActionsJCheckBoxHelper(isURLEncoded_incoming_QS);
		setActionsJCheckBoxHelper(isURLEncoded_incoming_body);
		setActionsJCheckBoxHelper(isURLEncoded_outgoing_QS);
		setActionsJCheckBoxHelper(isURLEncoded_outgoing_body);
		setActionsJCheckBoxHelper(isAllChar_URLEncoded_outgoing_QS);
		setActionsJCheckBoxHelper(isAllChar_URLEncoded_outgoing_body);
		setActionsJCheckBoxHelper(trimSpacesInContentTypeHeaderValues);
		setActionsJCheckBoxHelper(encodeNameValueOnlyMultipart);
		setActionsJCheckBoxHelper(use_incoming_charset_for_request_encoding);
		
		setActionsJTextFieldHelper(delimiter_QS);
		setActionsJTextFieldHelper(delimiter_QS_param);
		setActionsJTextFieldHelper(QS_equalSign);
		setActionsJTextFieldHelper(delimiter_urlencoded_body_param);
		setActionsJTextFieldHelper(body_param_equalSign);
		setActionsJTextFieldHelper(outgoing_request_encoding);
		setActionsJTextFieldHelper(incoming_request_encoding);
		
	}
	
	private void setActionsJCheckBoxHelper(JCheckBox checkbox) {
		checkbox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				comboBoxPolicy.setSelectedItem(policyOptions.custom);
				saveSettings();
			}
		});
	}
	
	private void setActionsJComboBoxHelper(JComboBox combobox) {
		combobox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				updateUIState();
				saveSettings();
			}
		});
	}
	
	private void setActionsJTextFieldHelper(JTextField textfield) {
		textfield.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent arg0) {
				comboBoxPolicy.setSelectedItem(policyOptions.custom);
				saveSettings();
			}
			@Override
			public void insertUpdate(DocumentEvent arg0) {
				comboBoxPolicy.setSelectedItem(policyOptions.custom);
				saveSettings();
			}
			@Override
			public void removeUpdate(DocumentEvent arg0) {
				comboBoxPolicy.setSelectedItem(policyOptions.custom);
				saveSettings();
			}
			});
	}
	
	private void loadSettings() {
		setValueFromExtensionSettings(comboBoxPolicy,"comboBoxPolicy",0);
		setValueFromExtensionSettings(preventReEncoding,"preventReEncoding",true);
		setValueFromExtensionSettings(encodeMicrosoftURLEncode,"encodeMicrosoftURLEncode",false);
		setValueFromExtensionSettings(encodeDespiteErrors,"encodeDespiteErrors",false);
		setValueFromExtensionSettings(addACharToEmptyBody,"addACharToEmptyBody",true);
		setValueFromExtensionSettings(replaceGETwithPOST,"replaceGETwithPOST",false);
		setValueFromExtensionSettings(isEncodable_QS,"isEncodable_QS",true);
		setValueFromExtensionSettings(isEncodable_body,"isEncodable_body",true);
		setValueFromExtensionSettings(isEncodable_QS_delimiter,"isEncodable_QS_delimiter",false);
		setValueFromExtensionSettings(isEncodable_urlencoded_body_delimiter,"isEncodable_urlencoded_body_delimiter",false);
		setValueFromExtensionSettings(isEncodable_QS_equal_sign,"isEncodable_QS_equal_sign",false);
		setValueFromExtensionSettings(isEncodable_urlencoded_body_equal_sign,"isEncodable_urlencoded_body_equal_sign",false);
		setValueFromExtensionSettings(isURLEncoded_incoming_QS,"isURLEncoded_incoming_QS",true);
		setValueFromExtensionSettings(isURLEncoded_incoming_body,"isURLEncoded_incoming_body",true);
		setValueFromExtensionSettings(isURLEncoded_outgoing_QS,"isURLEncoded_outgoing_QS",true);
		setValueFromExtensionSettings(isURLEncoded_outgoing_body,"isURLEncoded_outgoing_body",true);
		setValueFromExtensionSettings(isAllChar_URLEncoded_outgoing_QS,"isAllChar_URLEncoded_outgoing_QS",true);
		setValueFromExtensionSettings(isAllChar_URLEncoded_outgoing_body,"isAllChar_URLEncoded_outgoing_body",true);
		setValueFromExtensionSettings(trimSpacesInContentTypeHeaderValues,"trimSpacesInContentTypeHeaderValues",true);
		setValueFromExtensionSettings(encodeNameValueOnlyMultipart,"encodeNameValueOnlyMultipart",false);
		setValueFromExtensionSettings(use_incoming_charset_for_request_encoding,"use_incoming_charset_for_request_encoding",true);
		setValueFromExtensionSettings(delimiter_QS,"delimiter_QS","?");
		setValueFromExtensionSettings(delimiter_QS_param,"delimiter_QS_param","&");
		setValueFromExtensionSettings(QS_equalSign,"QS_equalSign","=");
		setValueFromExtensionSettings(delimiter_urlencoded_body_param,"delimiter_urlencoded_body_param","&");
		setValueFromExtensionSettings(body_param_equalSign,"body_param_equalSign","=");
		setValueFromExtensionSettings(outgoing_request_encoding,"outgoing_request_encoding","ibm500");
		setValueFromExtensionSettings(incoming_request_encoding,"incoming_request_encoding","utf-8");
	}

	private void saveSettings() {
		saveExtensionSettingHelper("comboBoxPolicy", comboBoxPolicy.getSelectedIndex());
		saveExtensionSettingHelper("preventReEncoding", preventReEncoding.isSelected());
		saveExtensionSettingHelper("encodeMicrosoftURLEncode", encodeMicrosoftURLEncode.isSelected());
		saveExtensionSettingHelper("encodeDespiteErrors", encodeDespiteErrors.isSelected());
		saveExtensionSettingHelper("addACharToEmptyBody", addACharToEmptyBody.isSelected());
		saveExtensionSettingHelper("replaceGETwithPOST", replaceGETwithPOST.isSelected());
		saveExtensionSettingHelper("isEncodable_QS", isEncodable_QS.isSelected());
		saveExtensionSettingHelper("isEncodable_body", isEncodable_body.isSelected());
		saveExtensionSettingHelper("isEncodable_QS_delimiter", isEncodable_QS_delimiter.isSelected());
		saveExtensionSettingHelper("isEncodable_urlencoded_body_delimiter", isEncodable_urlencoded_body_delimiter.isSelected());
		saveExtensionSettingHelper("isEncodable_QS_equal_sign", isEncodable_QS_equal_sign.isSelected());
		saveExtensionSettingHelper("isEncodable_urlencoded_body_equal_sign", isEncodable_urlencoded_body_equal_sign.isSelected());
		saveExtensionSettingHelper("delimiter_QS", delimiter_QS.getText());
		saveExtensionSettingHelper("delimiter_QS_param", delimiter_QS_param.getText());
		saveExtensionSettingHelper("QS_equalSign", QS_equalSign.getText());
		saveExtensionSettingHelper("delimiter_urlencoded_body_param", delimiter_urlencoded_body_param.getText());
		saveExtensionSettingHelper("body_param_equalSign", body_param_equalSign.getText());
		saveExtensionSettingHelper("isURLEncoded_incoming_QS", isURLEncoded_incoming_QS.isSelected());
		saveExtensionSettingHelper("isURLEncoded_incoming_body", isURLEncoded_incoming_body.isSelected());
		saveExtensionSettingHelper("isURLEncoded_outgoing_QS", isURLEncoded_outgoing_QS.isSelected());
		saveExtensionSettingHelper("isURLEncoded_outgoing_body", isURLEncoded_outgoing_body.isSelected());
		saveExtensionSettingHelper("isAllChar_URLEncoded_outgoing_QS", isAllChar_URLEncoded_outgoing_QS.isSelected());
		saveExtensionSettingHelper("isAllChar_URLEncoded_outgoing_body", isAllChar_URLEncoded_outgoing_body.isSelected());
		saveExtensionSettingHelper("trimSpacesInContentTypeHeaderValues", trimSpacesInContentTypeHeaderValues.isSelected());
		saveExtensionSettingHelper("encodeNameValueOnlyMultipart", encodeNameValueOnlyMultipart.isSelected());
		saveExtensionSettingHelper("outgoing_request_encoding", outgoing_request_encoding.getText());
		saveExtensionSettingHelper("use_incoming_charset_for_request_encoding", use_incoming_charset_for_request_encoding.isSelected());
		saveExtensionSettingHelper("incoming_request_encoding", incoming_request_encoding.getText());
	}
	
	private void resetSettings() {
		comboBoxPolicy.setSelectedIndex(0);
		updateUIState();
		saveSettings();		
	}

	private void saveExtensionSettingHelper(String name, Object value) {
		try {
			_callbacks.saveExtensionSetting(name, String.valueOf(value));
		}catch(Exception e) {
			_stderr.println(e.getMessage());
		}
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
	
	
	private void setValueFromExtensionSettings(JTextField jTextField, String name, Object defaultValue) {
		String value = _callbacks.loadExtensionSetting(name);
		if(value!=null && !value.equals("") && !value.equals(jTextField.getText())) {
			jTextField.setText(value);
		}else{
			jTextField.setText((String) defaultValue);
		}
	}
	
	private void setValueFromExtensionSettings(JComboBox jComboBox, String name, Object defaultValue) {
		String value = _callbacks.loadExtensionSetting(name);
		if(value!=null && !value.equals("")) {
			int temp_value = Integer.valueOf(value);
			if(temp_value!=jComboBox.getSelectedIndex())
				jComboBox.setSelectedIndex(temp_value);
		}else {
			jComboBox.setSelectedIndex((int) defaultValue);
		}
	}
	
	private void setValueFromExtensionSettings(JCheckBox jCheckBox, String name, Object defaultValue) {
		String value = _callbacks.loadExtensionSetting(name);
		if(value!=null && !value.equals("")) {
			boolean temp_value = Boolean.valueOf(value);
			if(temp_value!=jCheckBox.isSelected())
				jCheckBox.setSelected(temp_value);
		}else {
			jCheckBox.setSelected((boolean) defaultValue);
		}
	}
	
}
