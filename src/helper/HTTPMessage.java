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

package helper;

import java.awt.Component;
import java.awt.Container;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;

public class HTTPMessage {
	
	//private static String LWSP_Regex= "(([\\r\\n]|\\r\\n)[ \\t]+|[ \\t])*"; // https://tools.ietf.org/html/rfc5234 - ToDo -> add support of LWSP when finding header values
	
	// Reads the Content-Type value from the header - no LWSP support yet!  - reads the value before ";", "," or space
	public static String findHeaderContentType(String strHeader){
		String contentType="";
		if(!strHeader.equals("")){
			Pattern my_pattern = Pattern.compile("(?im)^content-type:[ \\t]*([^;,\\s]+)");
			Matcher m = my_pattern.matcher(strHeader);
			if (m.find()) {
				contentType = m.group(1);
			}
		}
		return contentType;
	}
	
	// Reads the Content-Type charset value from the header - no LWSP support yet! no support for double quotes around charset value either!
	public static String findCharsetFromHeader(String strHeader, boolean trimSpaces){
		String charset="";
		if(!strHeader.equals("")){
			Pattern my_pattern = Pattern.compile("(?im)^content-type:.*?[ \\t;,]+charset=[ \\t]*([\"]([^\"]+)[\"]|([^;\\s,]+))");
			Matcher m = my_pattern.matcher(strHeader);
			if (m.find()) {
				charset = m.group(1);
				charset = charset.replaceAll("\"", "");
				if (trimSpaces)
					charset = charset.trim();
			}
		}
		return charset;
	}
	
	// Reads the Content-Type boundary value from the header - no LWSP support yet! 
	public static String findBoundaryFromHeader(String strHeader, boolean trimSpaces){
		String boundary="";
		if(!strHeader.equals("")){
			Pattern my_pattern = Pattern.compile("(?im)^content-type:.*?[ \\t;,]+boundary=[ \\t]*([\"]([^\"]+)[\"]|([^\\s,]+))");
			Matcher m = my_pattern.matcher(strHeader);
			if (m.find()) {
				boundary = m.group(1);
				boundary = boundary.replaceAll("\"", "");
				if (trimSpaces)
					boundary = boundary.trim();
			}
		}
		return boundary;
	}
	
	// Makes a content-type header using provided parameters
	// Obviously the ; delimiter can be changed by comma in certain cases but that's not for discussion here!
	public static String createContentTypeHeader(String cType, String charset, String boundary, boolean trimSpaces){
		String contentType="";
		if(trimSpaces) {
			charset = charset.trim();
			boundary = boundary.trim();
		}
		
		if(charset.contains(" "))
			charset = "\""+charset+"\"";
		if(boundary.contains(" "))
			boundary = "\""+boundary+"\"";
		
		contentType = cType + "; charset=" + charset;
		
		if(!boundary.isEmpty()) {
			contentType = cType + "; boundary="+boundary + " ; charset=" + charset;
			// contentType = cType + "; charset=" + charset + ", boundary="+boundary; // another format
		}
		
		return contentType;
	}
	
	// Reads the Content-Type value from the header - reads the value before ";", "," or space
	public static String findHeaderContentType(List<String> headers){
		String contentType="";
		for(String strHeader : headers){
			if(!strHeader.equals("")){
				Pattern my_pattern = Pattern.compile("(?im)^content-type:[ \\t]*([^;, \\s]+)"); 
				Matcher m = my_pattern.matcher(strHeader);
				if (m.find()) {
					contentType = m.group(1);
					break;
				}
			}
		}
		return contentType;
	}
	
	
	// Splits header and body of a request or response
	public static String[] getHeaderAndBody(byte[] fullMessage,String encoding) throws UnsupportedEncodingException{
		String[] result = {"",""};
		String strFullMessage = "";
		if(fullMessage != null){
			// splitting the message to retrieve the header and the body
			strFullMessage = new String(fullMessage,encoding);
			if(strFullMessage.contains("\r\n\r\n"))
				result = strFullMessage.split("\r\n\r\n",2);
		}
		return result;
	}
	
	// Splits header and body of a request or response
	public static String[] getHeaderAndBody(String fullMessage) {
		String[] result = {"",""};
		if(fullMessage != null){
			// splitting the message to retrieve the header and the body
			if(fullMessage.contains("\r\n\r\n"))
				result = fullMessage.split("\r\n\r\n",2);
		}
		return result;
	}
	
	
	public static List<List<String>> getQueryString(String fullMessage){
		return getQueryString(fullMessage,  "" , "");
	}
	public static List<List<String>> getQueryString(String fullMessage, String delimiter_QS_param){
		return getQueryString(fullMessage,  "" , delimiter_QS_param);
	}
	// gets querystring parameters because burp can't handle special cases such as when we have jsessionid after ;
	public static List<List<String>> getQueryString(String reqMessage, String  delimiter_QS, String delimiter_QS_param){
		if (delimiter_QS.isEmpty()) delimiter_QS = "?";
		if (delimiter_QS_param.isEmpty()) delimiter_QS = "&";
		// final object with qs name and its value
		List<List<String>> qs_list = new ArrayList<List<String>>();
		
		// we assume that we are dealing with one HTTP message (not multiple in a pipeline)
		String firstline = reqMessage.split("\r\n|\r|\n", 2)[0]; 
		
		// we assume that we are dealing with an standard HTTP message in which there is a space after the last parameter value
		String QS = "";
		Pattern pattern = Pattern.compile("\\"+delimiter_QS+"([^ \\s]+)");
		Matcher matcher = pattern.matcher(firstline);
		if (matcher.find())
		{
			QS = matcher.group(1);
		}
		
		if (!QS.isEmpty()) {
			String[] keyValues = QS.split("\\"+delimiter_QS_param); 
			for(String keyValue:keyValues){
				List<String> keyValueList = new ArrayList<String>();
				String key = keyValue;
				String value = "";
				if(keyValue.contains("=")) {
					key = keyValue.split("=",2)[0];
					value = keyValue.split("=",2)[1];
				}
				keyValueList.add(key);
				keyValueList.add(value);
				qs_list.add(keyValueList);
			}
		}
		return qs_list;
	}
	
	
	public static List<List<String>> getURLEncodedBodyParams(String strMessage, boolean isBodyOnly){
		return getURLEncodedBodyParams(strMessage, isBodyOnly, "");
	}
	// gets URLEncoded POST parameters - it can use different delimiters than &
	public static List<List<String>> getURLEncodedBodyParams(String strMessage, boolean isBodyOnly, String delimiter_urlencoded_body_param){
		if (delimiter_urlencoded_body_param.isEmpty()) delimiter_urlencoded_body_param = "&";
		if(!isBodyOnly) {
			strMessage = getHeaderAndBody(strMessage)[1];
		}
		// final object with param name and its value
		List<List<String>> param_list = new ArrayList<List<String>>();
		String[] keyValues = strMessage.split("\\"+delimiter_urlencoded_body_param); 
		for(String keyValue:keyValues){
			List<String> keyValueList = new ArrayList<String>();
			String key = keyValue;
			String value = "";
			if(keyValue.contains("=")) {
				key = keyValue.split("=",2)[0];
				value = keyValue.split("=",2)[1];
			}
			keyValueList.add(key);
			keyValueList.add(value);
			param_list.add(keyValueList);
		}
		return param_list;
	}
	
	
	public static String replaceQueryString(String reqMessage, String newQS){
		return replaceQueryString(reqMessage, newQS, "");
	}
	// replaces querystring or adds it if empty in a request
	public static String replaceQueryString(String reqMessage, String newQS, String  delimiter_QS){
		String finalMessage = reqMessage;
		if (delimiter_QS.isEmpty()) delimiter_QS = "?";
		// we assume that we are dealing with one HTTP message (not multiple in a pipeline)
		String[] splittedRequest = reqMessage.split("\r\n|\r|\n", 2);
		String firstline = splittedRequest[0]; 
		firstline = firstline.trim(); // we don't have spaces before or after the first line if it is standard!
		
		String QS_pattern = "\\"+delimiter_QS+"[^ \\s]+";
		Pattern pattern = Pattern.compile(QS_pattern);
		Matcher matcher = pattern.matcher(firstline);
		if(matcher.find()) {
			// replacing existing QS
			firstline = matcher.replaceAll(delimiter_QS + newQS);
		}else {
			// adding QS to the request
			String HTTP_version_pattern = "([ ]+HTTP/[^ \\s]+)";
			pattern = Pattern.compile(HTTP_version_pattern);
			matcher = pattern.matcher(firstline);
			if(matcher.find()) {
				firstline = matcher.replaceAll(delimiter_QS + newQS + "$1");
			}else {
				// HTTP v0.9?!
				firstline += delimiter_QS + newQS;
			}
			
		}
		finalMessage = firstline + "\r\n" + splittedRequest[1];
		return finalMessage;
	}
	
	// get values of a header even when it is duplicated
	public static ArrayList<String> getHeaderValuesByName(List<String> headers, String headername){
		ArrayList<String> result = new ArrayList<String>();
		headername = headername.toLowerCase();
		for(String item:headers){
			if(item.indexOf(":")>=0){
				String[] headerItem = item.split(":",2);
				String headerNameLC = headerItem[0].toLowerCase();
				if(headerNameLC.equals(headername)){
					// We have a match
					result.add(headerItem[1].trim());
				}
			}
		}
		return result;
	}

	// get the first value of a header 
	public static String getHeaderValueByName(List<String> headers, String headerName){
		String result = "";
		headerName = headerName.toLowerCase();
		for(String item:headers){
			if(item.indexOf(":")>=0){
				String[] headerItem = item.split(":",2);
				String headerNameLC = headerItem[0].toLowerCase();
				if(headerNameLC.equals(headerName)){
					// We have a match
					result = headerItem[1].trim();
					break;
				}
			}
		}
		return result;
	}

	// replace a header value with the new value
	public static List<String> replaceHeaderValue(List<String> headers, String headerName, String newHeaderValue, boolean isCaseSensitive) {
		List<String> result = new ArrayList<String>();
		if(!isCaseSensitive)
			headerName = headerName.toLowerCase();
		int counter = 0;
		for(String item:headers){
			if(item.indexOf(":")>=0 && counter != 0){
				String[] headerItem = item.split(":",2);
				String headerNameForComp = headerItem[0];
				if(!isCaseSensitive)
					headerNameForComp = headerNameForComp.toLowerCase();
				if(headerNameForComp.equals(headerName)){
					// We have a match
					headerItem[1] = newHeaderValue;
				}
				result.add(headerItem[0]+": "+headerItem[1].trim());
			}else{
				result.add(item);
			}
			counter++;
		}
		return result;
	}
	
	// replace a header value with the new value
	public static String replaceHeaderValue(String strHeader, String headerName, String newHeaderValue, boolean isCaseSensitive) {
		String result = "";
		String header_pattern_string = "(?im)^("+Pattern.quote(headerName)+":).*$";
		if(isCaseSensitive) {
			header_pattern_string = "(?m)^("+Pattern.quote(headerName)+":).*$";
		}
			
		Pattern header_pattern = Pattern.compile(header_pattern_string);
		Matcher m = header_pattern.matcher(strHeader);
		if(m.find()) {
			// replacing
			result = m.replaceAll("$1 " + newHeaderValue);
		}else {
			// adding
			result = addHeader(strHeader, headerName, newHeaderValue);
		}
		return result;
	}
	
	// add a new header and its value - this is vulnerable to CRLF but that's intentional
	public static String addHeader(String strHeader, String newHeaderName, String newHeaderValue) {
		return addHeader(strHeader, newHeaderName + ": " +newHeaderValue);
	}
	
	// add a new header - this is vulnerable to CRLF but that's intentional
	public static String addHeader(String strHeader, String newHeader) {
		String result = "";
		// adding the new header to the second line after the HTTP version!
		result = strHeader.replaceFirst("([\r\n]+)", "$1"+newHeader+"$1");
		return result;
	}
	
	// replace a header verb with a new verb
	public static String replaceHeaderVerb(String strHeader, String newVerb) {
		String result = "";
		result = strHeader.replaceFirst("^[^ \t]+", newVerb);
		return result;
	}
}
