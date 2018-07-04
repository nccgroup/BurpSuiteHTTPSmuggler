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

package mutation;

public class HTTPEncodingObject {
	boolean preventReEncoding = true;
	boolean encodeMicrosoftURLEncode = true; // to encode utf-8 characters to their %uXXXX format
	boolean encodeDespiteErrors = false; // this will be ignored if encodeMicrosoftURLEncode=true
	boolean addACharToEmptyBody = true;
	boolean replaceGETwithPOST = false;
	boolean isEncodable_QS = true;
	boolean isEncodable_body = true;
	boolean isEncodable_QS_delimiter = false;
	boolean isEncodable_urlencoded_body_delimiter = false;
	boolean isEncodable_QS_equal_sign = false;
	boolean isEncodable_urlencoded_body_equal_sign = false;
	String delimiter_QS = "?";
	String delimiter_QS_param = "&";
	String QS_equalSign = "=";
	String delimiter_urlencoded_body_param = "&";
	String body_param_equalSign = "=";
	boolean isURLEncoded_incoming_QS = true; 
	boolean isURLEncoded_incoming_body = true; // this is not active when it is a multipart message
	boolean isURLEncoded_outgoing_QS = true;
	boolean isURLEncoded_outgoing_body = true; // this is not active when it is a multipart message
	boolean isAllChar_URLEncoded_outgoing_QS = true; // only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters
	boolean isAllChar_URLEncoded_outgoing_body = true; // only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters
	boolean trimSpacesInContentTypeHeaderValues = true; // IIS needs this, Apache does not!
	boolean encodeNameValueOnlyMultipart = false; // python django needs this, IIS does not!
	String outgoing_request_encoding = "ibm500";
	boolean use_incoming_charset_for_request_encoding = true;
	String incoming_request_encoding = "utf-8";
	public String[] normalEncodings = {"UTF-8", "UTF-16", "UTF-32", "ISO-8859-1"};
	
	public HTTPEncodingObject(boolean preventReEncoding, boolean encodeMicrosoftURLEncode, boolean encodeDespiteErrors,
			boolean addACharToEmptyBody, boolean replaceGETwithPOST, boolean isEncodable_QS, boolean isEncodable_body,
			boolean isEncodable_QS_delimiter, boolean isEncodable_urlencoded_body_delimiter,
			boolean isEncodable_QS_equal_sign, boolean isEncodable_urlencoded_body_equal_sign, String delimiter_QS,
			String delimiter_QS_param, String qS_equalSign, String delimiter_urlencoded_body_param,
			String body_param_equalSign, boolean isURLEncoded_incoming_QS, boolean isURLEncoded_incoming_body,
			boolean isURLEncoded_outgoing_QS, boolean isURLEncoded_outgoing_body,
			boolean isAllChar_URLEncoded_outgoing_QS, boolean isAllChar_URLEncoded_outgoing_body,
			boolean trimSpacesInContentTypeHeaderValues, boolean encodeNameValueOnlyMultipart,
			String outgoing_request_encoding, boolean use_incoming_charset_for_request_encoding,
			String incoming_request_encoding, String[] normalEncodings) {
		super();
		this.preventReEncoding = preventReEncoding;
		this.encodeMicrosoftURLEncode = encodeMicrosoftURLEncode;
		this.encodeDespiteErrors = encodeDespiteErrors;
		this.addACharToEmptyBody = addACharToEmptyBody;
		this.replaceGETwithPOST = replaceGETwithPOST;
		this.isEncodable_QS = isEncodable_QS;
		this.isEncodable_body = isEncodable_body;
		this.isEncodable_QS_delimiter = isEncodable_QS_delimiter;
		this.isEncodable_urlencoded_body_delimiter = isEncodable_urlencoded_body_delimiter;
		this.isEncodable_QS_equal_sign = isEncodable_QS_equal_sign;
		this.isEncodable_urlencoded_body_equal_sign = isEncodable_urlencoded_body_equal_sign;
		this.delimiter_QS = delimiter_QS;
		this.delimiter_QS_param = delimiter_QS_param;
		QS_equalSign = qS_equalSign;
		this.delimiter_urlencoded_body_param = delimiter_urlencoded_body_param;
		this.body_param_equalSign = body_param_equalSign;
		this.isURLEncoded_incoming_QS = isURLEncoded_incoming_QS;
		this.isURLEncoded_incoming_body = isURLEncoded_incoming_body;
		this.isURLEncoded_outgoing_QS = isURLEncoded_outgoing_QS;
		this.isURLEncoded_outgoing_body = isURLEncoded_outgoing_body;
		this.isAllChar_URLEncoded_outgoing_QS = isAllChar_URLEncoded_outgoing_QS;
		this.isAllChar_URLEncoded_outgoing_body = isAllChar_URLEncoded_outgoing_body;
		this.trimSpacesInContentTypeHeaderValues = trimSpacesInContentTypeHeaderValues;
		this.encodeNameValueOnlyMultipart = encodeNameValueOnlyMultipart;
		this.outgoing_request_encoding = outgoing_request_encoding;
		this.use_incoming_charset_for_request_encoding = use_incoming_charset_for_request_encoding;
		this.incoming_request_encoding = incoming_request_encoding;
		this.normalEncodings = normalEncodings;
	}
	
	public HTTPEncodingObject() {
		
	}

	public HTTPEncodingObject(String sampleType) {
		switch(sampleType.toLowerCase()) {
		case "jsp":
		case "jsp/tomcat":
			this.preventReEncoding = true;
			this.encodeMicrosoftURLEncode = false; // to encode utf-8 characters to their %uXXXX format
			this.encodeDespiteErrors = false; // this will be ignored if encodeMicrosoftURLEncode=true
			this.addACharToEmptyBody = false;
			this.replaceGETwithPOST = false;
			this.isEncodable_QS = false; // this is for JSP on Tomcat
			this.isEncodable_body = true;
			this.isEncodable_QS_delimiter = false;
			this.isEncodable_urlencoded_body_delimiter = false;
			this.isEncodable_QS_equal_sign = false;
			this.isEncodable_urlencoded_body_equal_sign = false;
			this.delimiter_QS = "?";
			this.delimiter_QS_param = "&";
			this.QS_equalSign = "=";
			this.delimiter_urlencoded_body_param = "&";
			this.body_param_equalSign = "=";
			this.isURLEncoded_incoming_QS = true; 
			this.isURLEncoded_incoming_body = true; // this is not active when it is a multipart message
			this.isURLEncoded_outgoing_QS = true;
			this.isURLEncoded_outgoing_body = true; // this is not active when it is a multipart message
			this.isAllChar_URLEncoded_outgoing_QS = true; // only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters
			this.isAllChar_URLEncoded_outgoing_body = true; // only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters
			this.trimSpacesInContentTypeHeaderValues = true; // similar to IIS and ASPX
			this.encodeNameValueOnlyMultipart = true; // probably won't work here... needs more testing
			this.outgoing_request_encoding = "ibm500";
			this.use_incoming_charset_for_request_encoding = true;
			this.incoming_request_encoding = "utf-8";
			break;
		
		case "py2":
		case "py2/django":
			this.preventReEncoding = true;
			this.encodeMicrosoftURLEncode = false; // to encode utf-8 characters to their %uXXXX format
			this.encodeDespiteErrors = false; // this will be ignored if encodeMicrosoftURLEncode=true
			this.addACharToEmptyBody = false;
			this.replaceGETwithPOST = false;
			this.isEncodable_QS = true; 
			this.isEncodable_body = true;
			this.isEncodable_QS_delimiter = false;
			this.isEncodable_urlencoded_body_delimiter = false;
			this.isEncodable_QS_equal_sign = false;
			this.isEncodable_urlencoded_body_equal_sign = false;
			this.delimiter_QS = "?";
			this.delimiter_QS_param = "&";
			this.QS_equalSign = "=";
			this.delimiter_urlencoded_body_param = "&";
			this.body_param_equalSign = "=";
			this.isURLEncoded_incoming_QS = true; 
			this.isURLEncoded_incoming_body = true; // this is not active when it is a multipart message
			this.isURLEncoded_outgoing_QS = true;
			this.isURLEncoded_outgoing_body = true; // this is not active when it is a multipart message
			this.isAllChar_URLEncoded_outgoing_QS = true; // only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters
			this.isAllChar_URLEncoded_outgoing_body = true; // only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters
			this.trimSpacesInContentTypeHeaderValues = true; // similar to IIS and ASPX
			this.encodeNameValueOnlyMultipart = true; // for python
			this.outgoing_request_encoding = "ibm500";
			this.use_incoming_charset_for_request_encoding = true;
			this.incoming_request_encoding = "utf-8";
			break;
		
		case "py3":
		case "py3/django":
			this.preventReEncoding = true;
			this.encodeMicrosoftURLEncode = false; // to encode utf-8 characters to their %uXXXX format
			this.encodeDespiteErrors = false; // this will be ignored if encodeMicrosoftURLEncode=true
			this.addACharToEmptyBody = false;
			this.replaceGETwithPOST = false;
			this.isEncodable_QS = true; 
			this.isEncodable_body = true;
			this.isEncodable_QS_delimiter = true;
			this.isEncodable_urlencoded_body_delimiter = true;
			this.isEncodable_QS_equal_sign = true;
			this.isEncodable_urlencoded_body_equal_sign = true;
			this.delimiter_QS = "?";
			this.delimiter_QS_param = "&";
			this.QS_equalSign = "=";
			this.delimiter_urlencoded_body_param = "&";
			this.body_param_equalSign = "=";
			this.isURLEncoded_incoming_QS = true; 
			this.isURLEncoded_incoming_body = true; // this is not active when it is a multipart message
			this.isURLEncoded_outgoing_QS = false;
			this.isURLEncoded_outgoing_body = false; // this is not active when it is a multipart message
			this.isAllChar_URLEncoded_outgoing_QS = false; // only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters
			this.isAllChar_URLEncoded_outgoing_body = false; // only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters
			this.trimSpacesInContentTypeHeaderValues = false; // similar to IIS and ASPX
			this.encodeNameValueOnlyMultipart = true; // for python
			this.outgoing_request_encoding = "ibm500";
			this.use_incoming_charset_for_request_encoding = true;
			this.incoming_request_encoding = "utf-8";
			break;

		case "aspx":
		case "aspx/iis":
			this.preventReEncoding = true;
			this.encodeMicrosoftURLEncode = true; // to encode utf-8 characters to their %uXXXX format
			this.encodeDespiteErrors = false; // this will be ignored if encodeMicrosoftURLEncode=true
			this.addACharToEmptyBody = true;
			this.replaceGETwithPOST = false;
			this.isEncodable_QS = true;
			this.isEncodable_body = true;
			this.isEncodable_QS_delimiter = false;
			this.isEncodable_urlencoded_body_delimiter = false;
			this.isEncodable_QS_equal_sign = false;
			this.isEncodable_urlencoded_body_equal_sign = false;
			this.delimiter_QS = "?";
			this.delimiter_QS_param = "&";
			this.QS_equalSign = "=";
			this.delimiter_urlencoded_body_param = "&";
			this.body_param_equalSign = "=";
			this.isURLEncoded_incoming_QS = true; 
			this.isURLEncoded_incoming_body = true; // this is not active when it is a multipart message
			this.isURLEncoded_outgoing_QS = true;
			this.isURLEncoded_outgoing_body = true; // this is not active when it is a multipart message
			this.isAllChar_URLEncoded_outgoing_QS = true; // only active when isURLEncoded_outgoing_QS=true to encode all characters rather than just key characters
			this.isAllChar_URLEncoded_outgoing_body = true; // only active when isURLEncoded_outgoing_body=true to encode all characters rather than just key characters
			this.trimSpacesInContentTypeHeaderValues = true; // IIS needs this, Apache does not!
			this.encodeNameValueOnlyMultipart = false; // python django needs this, IIS does not!
			this.outgoing_request_encoding = "ibm500";
			this.use_incoming_charset_for_request_encoding = true;
			this.incoming_request_encoding = "utf-8";
			break;
		}
	}
	
	public synchronized boolean isPreventReEncoding() {
		return preventReEncoding;
	}
	public synchronized void setPreventReEncoding(boolean preventReEncoding) {
		this.preventReEncoding = preventReEncoding;
	}
	public synchronized boolean isEncodeMicrosoftURLEncode() {
		return encodeMicrosoftURLEncode;
	}
	public synchronized void setEncodeMicrosoftURLEncode(boolean encodeMicrosoftURLEncode) {
		this.encodeMicrosoftURLEncode = encodeMicrosoftURLEncode;
	}
	public synchronized boolean isEncodeDespiteErrors() {
		return encodeDespiteErrors;
	}
	public synchronized void setEncodeDespiteErrors(boolean encodeDespiteErrors) {
		this.encodeDespiteErrors = encodeDespiteErrors;
	}
	public synchronized boolean isAddACharToEmptyBody() {
		return addACharToEmptyBody;
	}
	public synchronized void setAddACharToEmptyBody(boolean addACharToEmptyBody) {
		this.addACharToEmptyBody = addACharToEmptyBody;
	}
	public synchronized boolean isReplaceGETwithPOST() {
		return replaceGETwithPOST;
	}
	public synchronized void setReplaceGETwithPOST(boolean replaceGETwithPOST) {
		this.replaceGETwithPOST = replaceGETwithPOST;
	}
	public synchronized boolean isEncodable_QS() {
		return isEncodable_QS;
	}
	public synchronized void setEncodable_QS(boolean isEncodable_QS) {
		this.isEncodable_QS = isEncodable_QS;
	}
	public synchronized boolean isEncodable_body() {
		return isEncodable_body;
	}
	public synchronized void setEncodable_body(boolean isEncodable_body) {
		this.isEncodable_body = isEncodable_body;
	}
	public synchronized boolean isEncodable_QS_delimiter() {
		return isEncodable_QS_delimiter;
	}
	public synchronized void setEncodable_QS_delimiter(boolean isEncodable_QS_delimiter) {
		this.isEncodable_QS_delimiter = isEncodable_QS_delimiter;
	}
	public synchronized boolean isEncodable_urlencoded_body_delimiter() {
		return isEncodable_urlencoded_body_delimiter;
	}
	public synchronized void setEncodable_urlencoded_body_delimiter(boolean isEncodable_urlencoded_body_delimiter) {
		this.isEncodable_urlencoded_body_delimiter = isEncodable_urlencoded_body_delimiter;
	}
	public synchronized boolean isEncodable_QS_equal_sign() {
		return isEncodable_QS_equal_sign;
	}
	public synchronized void setEncodable_QS_equal_sign(boolean isEncodable_QS_equal_sign) {
		this.isEncodable_QS_equal_sign = isEncodable_QS_equal_sign;
	}
	public synchronized boolean isEncodable_urlencoded_body_equal_sign() {
		return isEncodable_urlencoded_body_equal_sign;
	}
	public synchronized void setEncodable_urlencoded_body_equal_sign(boolean isEncodable_urlencoded_body_equal_sign) {
		this.isEncodable_urlencoded_body_equal_sign = isEncodable_urlencoded_body_equal_sign;
	}
	public synchronized String getDelimiter_QS() {
		return delimiter_QS;
	}
	public synchronized void setDelimiter_QS(String delimiter_QS) {
		this.delimiter_QS = delimiter_QS;
	}
	public synchronized String getDelimiter_QS_param() {
		return delimiter_QS_param;
	}
	public synchronized void setDelimiter_QS_param(String delimiter_QS_param) {
		this.delimiter_QS_param = delimiter_QS_param;
	}
	public synchronized String getQS_equalSign() {
		return QS_equalSign;
	}
	public synchronized void setQS_equalSign(String qS_equalSign) {
		QS_equalSign = qS_equalSign;
	}
	public synchronized String getDelimiter_urlencoded_body_param() {
		return delimiter_urlencoded_body_param;
	}
	public synchronized void setDelimiter_urlencoded_body_param(String delimiter_urlencoded_body_param) {
		this.delimiter_urlencoded_body_param = delimiter_urlencoded_body_param;
	}
	public synchronized String getBody_param_equalSign() {
		return body_param_equalSign;
	}
	public synchronized void setBody_param_equalSign(String body_param_equalSign) {
		this.body_param_equalSign = body_param_equalSign;
	}
	public synchronized boolean isURLEncoded_incoming_QS() {
		return isURLEncoded_incoming_QS;
	}
	public synchronized void setURLEncoded_incoming_QS(boolean isURLEncoded_incoming_QS) {
		this.isURLEncoded_incoming_QS = isURLEncoded_incoming_QS;
	}
	public synchronized boolean isURLEncoded_incoming_body() {
		return isURLEncoded_incoming_body;
	}
	public synchronized void setURLEncoded_incoming_body(boolean isURLEncoded_incoming_body) {
		this.isURLEncoded_incoming_body = isURLEncoded_incoming_body;
	}
	public synchronized boolean isURLEncoded_outgoing_QS() {
		return isURLEncoded_outgoing_QS;
	}
	public synchronized void setURLEncoded_outgoing_QS(boolean isURLEncoded_outgoing_QS) {
		this.isURLEncoded_outgoing_QS = isURLEncoded_outgoing_QS;
	}
	public synchronized boolean isAllChar_URLEncoded_outgoing_QS() {
		return isAllChar_URLEncoded_outgoing_QS;
	}
	public synchronized void setAllChar_URLEncoded_outgoing_QS(boolean isAllChar_URLEncoded_outgoing_QS) {
		this.isAllChar_URLEncoded_outgoing_QS = isAllChar_URLEncoded_outgoing_QS;
	}
	public synchronized boolean isURLEncoded_outgoing_body() {
		return isURLEncoded_outgoing_body;
	}
	public synchronized void setURLEncoded_outgoing_body(boolean isURLEncoded_outgoing_body) {
		this.isURLEncoded_outgoing_body = isURLEncoded_outgoing_body;
	}
	public synchronized boolean isAllChar_URLEncoded_outgoing_body() {
		return isAllChar_URLEncoded_outgoing_body;
	}
	public synchronized void setAllChar_URLEncoded_outgoing_body(boolean isAllChar_URLEncoded_outgoing_body) {
		this.isAllChar_URLEncoded_outgoing_body = isAllChar_URLEncoded_outgoing_body;
	}
	public synchronized boolean isTrimSpacesInContentTypeHeaderValues() {
		return trimSpacesInContentTypeHeaderValues;
	}
	public synchronized void setTrimSpacesInContentTypeHeaderValues(boolean trimSpacesInContentTypeHeaderValues) {
		this.trimSpacesInContentTypeHeaderValues = trimSpacesInContentTypeHeaderValues;
	}
	public synchronized boolean isEncodeNameValueOnlyMultipart() {
		return encodeNameValueOnlyMultipart;
	}
	public synchronized void setEncodeNameValueOnlyMultipart(boolean encodeNameValueOnlyMultipart) {
		this.encodeNameValueOnlyMultipart = encodeNameValueOnlyMultipart;
	}
	public synchronized String getOutgoing_request_encoding() {
		return outgoing_request_encoding;
	}
	public synchronized void setOutgoing_request_encoding(String outgoing_request_encoding) {
		this.outgoing_request_encoding = outgoing_request_encoding;
	}
	public synchronized boolean isUse_incoming_charset_for_request_encoding() {
		return use_incoming_charset_for_request_encoding;
	}
	public synchronized void setUse_incoming_charset_for_request_encoding(
			boolean use_incoming_charset_for_request_encoding) {
		this.use_incoming_charset_for_request_encoding = use_incoming_charset_for_request_encoding;
	}
	public synchronized String getIncoming_request_encoding() {
		return incoming_request_encoding;
	}
	public synchronized void setIncoming_request_encoding(String incoming_request_encoding) {
		this.incoming_request_encoding = incoming_request_encoding;
	}
	public synchronized String[] getNormalEncodings() {
		return normalEncodings;
	}
	public synchronized void setNormalEncodings(String[] normalEncodings) {
		this.normalEncodings = normalEncodings;
	}
	
}
