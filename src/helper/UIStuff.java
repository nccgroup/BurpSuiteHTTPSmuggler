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
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;

public class UIStuff {

	// Show a message to the user
	public static void showMessage(final String strMsg){
		new Thread(new Runnable()
		{
			@Override
			public void run()
			{
				JOptionPane.showMessageDialog(null, strMsg);
			}
		}).start();
		
	}
	
	// Show a message to the user
	public static void showWarningMessage(final String strMsg){
		new Thread(new Runnable()
		{
			@Override
			public void run()
			{
				JOptionPane.showMessageDialog(null, strMsg, "Warning", JOptionPane.WARNING_MESSAGE);
			}
		}).start();
		
	}
	
	// Show a message to the user
	public static String showPlainInputMessage(final String strMessage, final String strTitle, final String defaultValue){
			String output = (String)JOptionPane.showInputDialog(null, 
						strMessage,strTitle,JOptionPane.PLAIN_MESSAGE, null, null, defaultValue); 
			if(output==null){
				output = defaultValue;
			}
			return output;	
	}
	
	// Common method to ask a multiple question
	public static Integer askConfirmMessage(final String strTitle, final String strQuestion, String[] msgOptions){
		final Object[] options = msgOptions;
	    final int[] choice = new int[1];
	    choice[0] = 0;
	    choice[0] = JOptionPane.showOptionDialog(null,
					strQuestion,
					strTitle,
					JOptionPane.YES_NO_CANCEL_OPTION,
					JOptionPane.QUESTION_MESSAGE,
					null,
					options,
					options[0]);
	    return choice[0];
	}
	
	// to update the JCheckbox background colour after using the customizeUiComponent() method
	public static void updateJCheckBoxBackground(Container c) {
	    Component[] components = c.getComponents();
	    for(Component com : components) {
	        if(com instanceof JCheckBox) {
	        	com.setBackground(c.getBackground());
	        } else if(com instanceof Container) {
	        	updateJCheckBoxBackground((Container) com);
	        }
	    }
	}
}
