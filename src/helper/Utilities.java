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

public class Utilities {
	private static final char[] hexChar = {
			'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
	};
	
	public static String URLEncodeAll(String input) {
		return URLEncode(input, "");
	}

	public static String URLEncodeSpecial(String input, String specialChars) {
		if (specialChars.isEmpty()) specialChars = "!#$&'()*+,/:;=?@[] \"%-.<>\\^_`{|}~";
		return URLEncode(input, specialChars);
	}

	public static String URLEncodeSpecial(String input) {
		return URLEncodeSpecial(input, "");
	}

	public static String URLEncode(String input, String specialChars) {
		// idea from https://codereview.stackexchange.com/questions/102591/efficient-url-escape-percent-encoding
		if (input == null || input.isEmpty()) {
			return input;
		}
		StringBuilder result = new StringBuilder(input);
		for (int i = input.length() - 1; i >= 0; i--) {
			if(specialChars.isEmpty()) {
				result.replace(i, i + 1, "%" + String.format("%2s",Integer.toHexString(input.charAt(i))).replace(' ', '0').toUpperCase());
			}else if(specialChars.indexOf(input.charAt(i)) != -1) {
				result.replace(i, i + 1, "%" + String.format("%2s",Integer.toHexString(input.charAt(i)).replace(' ', '0').toUpperCase()));
			}
		}
		return result.toString();
	}

	public static String URLEncodeAllBytes(byte[] input) {
		// idea from https://codereview.stackexchange.com/questions/102591/efficient-url-escape-percent-encoding
		if (input == null) {
			return "";
		}
		StringBuilder result = new StringBuilder();
		for (byte b: input) {
			result.append("%" + String.format("%02x", b).toUpperCase());
		}
		return result.toString();
	}

	// https://docs.oracle.com/javase/tutorial/i18n/text/examples/UnicodeFormatter.java
	static public String byteToHex(byte b) {
		// Returns hex String representation of byte b
		char[] array = { hexChar[(b >> 4) & 0x0f], hexChar[b & 0x0f] };
		return new String(array);
	}

	// https://docs.oracle.com/javase/tutorial/i18n/text/examples/UnicodeFormatter.java
	static public String charToHex(char c) {
		// Returns hex String representation of char c
		byte hi = (byte) (c >>> 8);
		byte lo = (byte) (c & 0xff);
		return byteToHex(hi) + byteToHex(lo);
	}

	
	// http://www.xinotes.net/notes/note/812/
	static public String unicodeEscape(String s, boolean encodeAll, boolean isURL) {
		StringBuilder sb = new StringBuilder();
		String escapePrefix = "\\u";
		if(isURL) escapePrefix = "%u";
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if ((c >> 7) > 0 || encodeAll) {
				sb.append(escapePrefix);
				sb.append(hexChar[(c >> 12) & 0xF]); // append the hex character for the left-most 4-bits
				sb.append(hexChar[(c >> 8) & 0xF]);  // hex for the second group of 4-bits from the left
				sb.append(hexChar[(c >> 4) & 0xF]);  // hex for the third group
				sb.append(hexChar[c & 0xF]);         // hex for the last group, e.g., the right most 4-bits
			}
			else {
				sb.append(c);
			}
		}
		return sb.toString();
	}
	

}
