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

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
//import java.nio.ByteBuffer;
//import java.nio.CharBuffer;
import java.nio.charset.Charset;
//import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
//import burp.IRequestInfo;

public class HttpEncoding {
	private boolean isDebug = false;
	private IBurpExtenderCallbacks _callbacks;
	private IExtensionHelpers _helpers;
	private PrintWriter _stdout;
	private PrintWriter _stderr;
	private HTTPEncodingObject currentHTTPEncodingObject = new HTTPEncodingObject();

	public HttpEncoding(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		_callbacks = callbacks;
		_helpers = _callbacks.getHelpers();
		_stdout = stdout;
		_stderr = stderr;
		this.isDebug = isDebug; 
	}

	private void showDebugMessage(Object object) {
		if(isDebug)
			_stdout.println(object.toString());
	}

	private String encode(String inputStr, boolean URLEncodeResult, boolean URLEncodeAll) throws Exception {
		String result = "";
		if(currentHTTPEncodingObject.encodeMicrosoftURLEncode) {
			// We want to encode characters that are ASCII readable and the rest should be encoded using %uXXXX format
			StringBuilder sb = new StringBuilder();
			String MSEncodedInputStr = helper.Utilities.unicodeEscape(inputStr, false, true);
			String[] MSEncodedInputStrSplitted = MSEncodedInputStr.split("%u");
			int counter = 0;
			for(String str:MSEncodedInputStrSplitted) {
				if(str.length()>0) {
					String tempStr = "";
					if(counter==0) {
						tempStr = encode(str, currentHTTPEncodingObject.outgoing_request_encoding);
					}else {
						sb.append("%u"+str.substring(0, 4));
						if(str.length()>4)
							tempStr = encode(str.substring(4), currentHTTPEncodingObject.outgoing_request_encoding);
					}
					if(tempStr.length()>0) {
						if(URLEncodeResult){
							if(URLEncodeAll) {
								tempStr = helper.Utilities.URLEncodeAll(tempStr);
							}else {
								tempStr = _helpers.urlEncode(tempStr);
							}
						}
						sb.append(tempStr);
					}
				}
				counter++;
			}
			result = sb.toString();
		}else {
			if(!currentHTTPEncodingObject.encodeDespiteErrors) {
				// Detecting if there is a character that can be encoded to something like \\u[NotZero][NotZero]XX
				boolean hasHigherUTF8 = false;
				char[] hexChar = {
						'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
				};
				for (int i = 0; i < inputStr.length(); i++) {
					char c = inputStr.charAt(i);
					if ((c >> 7) > 0) {
						if(hexChar[(c >> 12) & 0xF]!=0 || hexChar[(c >> 8) & 0xF]!=0) {
							hasHigherUTF8 = true;
						}
					}
				}
				if(hasHigherUTF8) {
					showDebugMessage("Error in encoding , a character will be converted to a \"?\".");
					throw new Exception("\"Message could not be encoded properly - try it with encodeDespiteErrors=True or encodeMicrosoftURLEncode=True if the request does not change anything on the server\"");
				}
			}
			result = encode(inputStr, currentHTTPEncodingObject.outgoing_request_encoding);
			if(URLEncodeResult){
				if(URLEncodeAll) {
					result = helper.Utilities.URLEncodeAll(result);
				}else {
					result = _helpers.urlEncode(result);
				}
			}
		}

		return result;
	}

	public String encode(String strInput,String outgoingEncoding) {
		String result = strInput;
		if(outgoingEncoding.isEmpty()) outgoingEncoding = currentHTTPEncodingObject.outgoing_request_encoding;
		try{
			showDebugMessage("Encode method using outgoingEncoding: " + outgoingEncoding);
			showDebugMessage("strInput: " + strInput);
			result = new String(strInput.getBytes(outgoingEncoding), "ISO-8859-1");
			if(outgoingEncoding.startsWith("ibm") || outgoingEncoding.startsWith("cp")) {
				// to support ibm.swapLF=true - see https://stackoverflow.com/questions/24633276/encoding-strangeness-with-cp500-lf-nel
				result=result.replaceAll("(?im)\\x15", "%");
			}
			//long questionMarkCounterAfter = result.chars().filter(ch -> ch == '?').count();
			showDebugMessage("result: " + result);
		}catch(UnsupportedEncodingException e){
			_stderr.println(e.getMessage());
		}
		return result;
	}

	public String encodeHTTPMessage(burp.IHttpRequestResponse iHttpRequestResponse, String incomingEncoding, String outgoingEncoding) throws UnsupportedEncodingException {
		return encodeHTTPMessage(iHttpRequestResponse.getRequest(), incomingEncoding, outgoingEncoding);
	}


	public String encodeHTTPMessage(byte[] fullMessageByte,String incomingEncoding, String outgoingEncoding) throws UnsupportedEncodingException {
		boolean hasSomethingChanged = false;
		if (incomingEncoding.isEmpty()) incomingEncoding = currentHTTPEncodingObject.incoming_request_encoding;
		String fullMessage = new String(fullMessageByte,incomingEncoding);
		//IRequestInfo requestInfo = _helpers.analyzeRequest(fullMessageByte);
		String encodedRequest = "";
		String validContentType = "";
		String[] acceptable_content_types = {"application/x-www-form-urlencoded","multipart/form-data","xml","json"};
		if(outgoingEncoding.isEmpty()) outgoingEncoding = currentHTTPEncodingObject.outgoing_request_encoding;
		String[] headerBody = helper.HTTPMessage.getHeaderAndBody(fullMessage);
		String header = headerBody[0];
		String body = headerBody[1];
		String content_type = helper.HTTPMessage.findHeaderContentType(header);
		String charset = helper.HTTPMessage.findCharsetFromHeader(header, currentHTTPEncodingObject.trimSpacesInContentTypeHeaderValues).toUpperCase();
		
		if(currentHTTPEncodingObject.use_incoming_charset_for_request_encoding && Charset.availableCharsets().keySet().contains(charset)) {
			currentHTTPEncodingObject.incoming_request_encoding = charset;
		}
		
		if(currentHTTPEncodingObject.preventReEncoding && !charset.isEmpty() && !(Arrays.asList(currentHTTPEncodingObject.normalEncodings).contains(currentHTTPEncodingObject.incoming_request_encoding))) {
			showDebugMessage("The request seems to be encoded already using " + charset + " that is not one of " + Arrays.asList(currentHTTPEncodingObject.normalEncodings).toString());
			return "";
		}

		//List<List<String>> QS_params = new ArrayList<List<String>>();

		showDebugMessage("content-type was: " + content_type);

		for (String acceptable_content_type : acceptable_content_types) {
			if(content_type.toLowerCase().contains(acceptable_content_type)) {
				validContentType = acceptable_content_type;
				break;
			}
		}

		try {
			if(currentHTTPEncodingObject.isEncodable_QS) {
				List<List<String>> original_qs_params = helper.HTTPMessage.getQueryString(header, currentHTTPEncodingObject.delimiter_QS, currentHTTPEncodingObject.delimiter_QS_param);
				showDebugMessage("QueryString:");
				showDebugMessage(original_qs_params);
				String newQueryString = "";

				if(currentHTTPEncodingObject.isEncodable_QS_delimiter) {
					currentHTTPEncodingObject.delimiter_QS = encode(currentHTTPEncodingObject.delimiter_QS, false, false);
				}
				if (currentHTTPEncodingObject.isEncodable_QS_equal_sign) {
					currentHTTPEncodingObject.QS_equalSign = encode(currentHTTPEncodingObject.QS_equalSign, false, false);
				}
				// the parameters might be url encoded - we need to decode them before mutation!
				// in the future, burp converter should be replaced really so this class can be used independently
				for(List<String> item:original_qs_params) {
					String param_name = item.get(0);
					String param_value = item.get(1);
					if(currentHTTPEncodingObject.isURLEncoded_incoming_QS){				
						// Burp Sutie can't handle utf-8 in URL decoding! e.g.: _helpers.urlDecode("تست")
						param_name = new String(_helpers.urlDecode(param_name.getBytes("ISO-8859-1")),currentHTTPEncodingObject.incoming_request_encoding);
						//param_name = new String(param_name.getBytes());
						param_value = new String(_helpers.urlDecode(param_value.getBytes("ISO-8859-1")),currentHTTPEncodingObject.incoming_request_encoding);
					}
					String param_name_encoded = encode(param_name, currentHTTPEncodingObject.isURLEncoded_outgoing_QS, currentHTTPEncodingObject.isAllChar_URLEncoded_outgoing_QS);
					String param_value_encoded = encode(param_value, currentHTTPEncodingObject.isURLEncoded_outgoing_QS, currentHTTPEncodingObject.isAllChar_URLEncoded_outgoing_QS);

					if(!newQueryString.isEmpty()) {
						newQueryString += currentHTTPEncodingObject.delimiter_QS_param;
					}
					newQueryString += param_name_encoded + currentHTTPEncodingObject.QS_equalSign + param_value_encoded;
				}
				if(!newQueryString.isEmpty()) {
					hasSomethingChanged = true;
					header = helper.HTTPMessage.replaceQueryString(header,newQueryString);
					showDebugMessage(header);
				}
			}

			if(!validContentType.isEmpty()) {

				if(currentHTTPEncodingObject.isEncodable_body && body.length()>0) {
					// encoding body
					switch(validContentType) {
					case "application/x-www-form-urlencoded":
						List<List<String>> original_body_params = helper.HTTPMessage.getURLEncodedBodyParams(body, true, currentHTTPEncodingObject.delimiter_urlencoded_body_param);
						showDebugMessage("Body Params:");
						showDebugMessage(original_body_params);
						String newBodyParams = "";
						if(currentHTTPEncodingObject.isEncodable_urlencoded_body_delimiter) {
							currentHTTPEncodingObject.delimiter_urlencoded_body_param = encode(currentHTTPEncodingObject.delimiter_urlencoded_body_param, false, false);
						}
						if (currentHTTPEncodingObject.isEncodable_urlencoded_body_equal_sign) {
							currentHTTPEncodingObject.body_param_equalSign = encode(currentHTTPEncodingObject.body_param_equalSign, false, false);
						}
						// the parameters might be url encoded - we need to decode them before mutation!
						// in the future, burp converter should be replaced really so this class can be used independently
						for(List<String> item:original_body_params) {
							String param_name = item.get(0);
							String param_value = item.get(1);
							if(currentHTTPEncodingObject.isURLEncoded_incoming_body){				
								// Burp Sutie can't handle utf-8 in URL decoding! e.g.: _helpers.urlDecode("تست")
								param_name = new String(_helpers.urlDecode(param_name.getBytes("ISO-8859-1")),currentHTTPEncodingObject.incoming_request_encoding);
								//param_name = new String(param_name.getBytes());
								param_value = new String(_helpers.urlDecode(param_value.getBytes("ISO-8859-1")),currentHTTPEncodingObject.incoming_request_encoding);
							}
							String param_name_encoded = encode(param_name, currentHTTPEncodingObject.isURLEncoded_outgoing_body, currentHTTPEncodingObject.isAllChar_URLEncoded_outgoing_body);
							String param_value_encoded = encode(param_value, currentHTTPEncodingObject.isURLEncoded_outgoing_body, currentHTTPEncodingObject.isAllChar_URLEncoded_outgoing_body);

							if(!newBodyParams.isEmpty()) {
								newBodyParams += currentHTTPEncodingObject.delimiter_urlencoded_body_param;
							}
							newBodyParams += param_name_encoded + currentHTTPEncodingObject.body_param_equalSign + param_value_encoded;
						}

						if(!newBodyParams.isEmpty()) {
							body = newBodyParams;
							hasSomethingChanged = true;
						}

						break;
					case "multipart/form-data":
						// find the boundary value from the content-type header
						String boundaryValue = helper.HTTPMessage.findBoundaryFromHeader(header, currentHTTPEncodingObject.trimSpacesInContentTypeHeaderValues);
						if(!charset.equals("UTF-8") && !charset.isEmpty()) {
							_stdout.println("Charset is "+charset + " in a MultiPart message, message has probably been corrupted already :(");
						}
						if(!boundaryValue.isEmpty()) {
							// we need to parse it... yes and here is the source of another canonical issue :p
							StringBuilder finalBody = new StringBuilder("");
							String [] bodyparts;
							bodyparts = body.split("[\r]?[\n]?\\-\\-"+Pattern.quote(boundaryValue)+"(\\-\\-)?[\r]?[\n]?");
							if(bodyparts.length > 1) {
								for(int i=0; i < bodyparts.length; i++) {
									String bodypart = bodyparts[i];
									String [] bodypart_header_body;
									if(bodypart.isEmpty() && i < bodyparts.length-1) {
										if(finalBody.length()>0)
											finalBody.append("\r\n");
										finalBody.append("--");
										finalBody.append(boundaryValue);
									}else {
										bodypart_header_body = bodypart.split("\r\n\r\n",2);
										if(bodypart_header_body.length==2) {
											String part_header_encoded = "";
											String part_body_encoded = "";
											if(currentHTTPEncodingObject.encodeNameValueOnlyMultipart) {
												// Example: python Django needs to encode the name value rather than the whole header
												String nameRegEx = "(Content\\-Disposition: .*name=[\"])([^\"]+)(.*)";
												Pattern pattern_param_name = Pattern.compile(nameRegEx);
												Matcher matcher_param_name = pattern_param_name.matcher(bodypart_header_body[0]);
												if (matcher_param_name.find())
												{
													String param_name = matcher_param_name.group(2);
													String param_name_encoded = encode(param_name, false, false);
													part_header_encoded = bodypart_header_body[0].replaceAll(nameRegEx, "$1"+param_name_encoded+"$3");
												}else {
													part_header_encoded = bodypart_header_body[0];
												}
												part_body_encoded = encode(bodypart_header_body[1], false, false);
											}else {
												// Example: IIS needs the full header being encoded but line by line!
												// Assuming CR LF is used - otherwise we need to split it differently :(
												String[] partHeaderArray = bodypart_header_body[0].split("[\r\n]");
												for(String partHeaderLine:partHeaderArray) {
													if(!partHeaderLine.isEmpty()) {
														if(part_header_encoded.isEmpty())
															part_header_encoded = encode(partHeaderLine, false, false);
														else
															part_header_encoded += "\r\n" + encode(partHeaderLine, false, false);
													}
												}
												//part_header_encoded = encode(bodypart_header_body[0], false, false);
												part_body_encoded = encode(bodypart_header_body[1], false, false);
											}
											if(finalBody.length()>0)
												finalBody.append("\r\n");
											finalBody.append(part_header_encoded);
											finalBody.append("\r\n\r\n");
											finalBody.append(part_body_encoded);
											finalBody.append("\r\n--");
											finalBody.append(boundaryValue);
										}else {
											String bodypart_encoded = encode(bodypart, false, false);
											finalBody.append("--");
											finalBody.append(boundaryValue);
											finalBody.append("\r\n");
											finalBody.append(bodypart_encoded);
											finalBody.append("\r\n");
										}
									}

								}
								finalBody.append("--\r\n");
								body = finalBody.toString();

								content_type = helper.HTTPMessage.createContentTypeHeader(content_type, currentHTTPEncodingObject.outgoing_request_encoding, boundaryValue, currentHTTPEncodingObject.trimSpacesInContentTypeHeaderValues);
								hasSomethingChanged = true;
							}
						}
						break;
					case "json":
					case "xml":
						body = encode(body, false, false);
						hasSomethingChanged = true;
						break;
					}
				}
			}else {
				content_type = "application/x-www-form-urlencoded";
			}

		}catch(Exception e) {
			_stderr.println(e.getMessage());
			return "";
		}

		if(hasSomethingChanged) {
			if(currentHTTPEncodingObject.addACharToEmptyBody && body.length()==0) {
				body = " ";
			}

			if(currentHTTPEncodingObject.replaceGETwithPOST) {
				header = helper.HTTPMessage.replaceHeaderVerb(header, "POST");
			}

			if(!content_type.contains("charset")) {
				content_type = helper.HTTPMessage.createContentTypeHeader(content_type, currentHTTPEncodingObject.outgoing_request_encoding, "", currentHTTPEncodingObject.trimSpacesInContentTypeHeaderValues);
			}

			header = helper.HTTPMessage.replaceHeaderValue(header, "content-length", String.valueOf(body.length()), false);
			header = helper.HTTPMessage.replaceHeaderValue(header, "content-type", content_type, false);
			encodedRequest = header+"\r\n\r\n"+body;
			return encodedRequest;
		}else {
			return "";
		}

	}

	public String encodeHTTPMessage(byte[] request, HTTPEncodingObject selectedHTTPEncodingObject) throws UnsupportedEncodingException {
		currentHTTPEncodingObject = selectedHTTPEncodingObject;
		return encodeHTTPMessage(request, currentHTTPEncodingObject.incoming_request_encoding, currentHTTPEncodingObject.outgoing_request_encoding);
	}


}
