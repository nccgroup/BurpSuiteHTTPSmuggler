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

import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;

public class BurpFunctions {
	public static Object loadExtensionSettingHelper(String name, String type, Object defaultValue,IBurpExtenderCallbacks callbacks,  PrintWriter stderr) {
		Object value = null;
		try {
			String temp_value = callbacks.loadExtensionSetting(name);
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
			stderr.println(e.getMessage());
		}

		if(value==null) {
			value = defaultValue;
		}
		return value;
	}
}
