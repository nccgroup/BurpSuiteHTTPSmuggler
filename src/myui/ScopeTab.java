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

/*
 * TODO: implement OR + AND-NOT + OR-NOT
 * */
import javax.swing.JPanel;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

public class ScopeTab extends JPanel {
	private IBurpExtenderCallbacks _callbacks;;
	private IExtensionHelpers _helpers;
	private PrintWriter _stdout;
	private PrintWriter _stderr;

	/**
	 * Create the panel.
	 */

	public enum scopeOptions1{
		AND,
		OR,
		DISABLED
	}
	
	public enum scopeOptions2{
		ENABLED,
		DISABLED
	}

	private JComboBox targetScopeOption;
	private JComboBox pathRegExOption;
	private JTextField pathRegEx;
	private JComboBox headerRegExOption;
	private JTextField headerRegEx;
	private JCheckBox chckbxAllTools;
	private JCheckBox chckbxProxy;
	private JCheckBox chckbxScanner;
	private JCheckBox chckbxIntruder;
	private JCheckBox chckbxRepeator;
	private JCheckBox chckbxExtender;
	private JCheckBox chckbxTarget;
	private JCheckBox chckbxSequencer;
	private JCheckBox chckbxSpider;

	public ScopeTab(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
		_callbacks = callbacks;
		_helpers = _callbacks.getHelpers();
		_stdout = stdout;
		_stderr = stderr;

		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{30, 0, 30, 101, 221, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);


		JLabel lblIn = new JLabel("In Burp Target scope?");
		GridBagConstraints gbc_lblIn = new GridBagConstraints();
		gbc_lblIn.anchor = GridBagConstraints.EAST;
		gbc_lblIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblIn.gridx = 2;
		gbc_lblIn.gridy = 2;
		add(lblIn, gbc_lblIn);

		targetScopeOption = new JComboBox();
		targetScopeOption.setModel(new DefaultComboBoxModel(scopeOptions2.values()));
		GridBagConstraints gbc_targetScopeOption = new GridBagConstraints();
		gbc_targetScopeOption.anchor = GridBagConstraints.WEST;
		gbc_targetScopeOption.insets = new Insets(0, 0, 5, 5);
		gbc_targetScopeOption.gridx = 3;
		gbc_targetScopeOption.gridy = 2;
		add(targetScopeOption, gbc_targetScopeOption);

		JLabel lblPathRegex = new JLabel("Path/URL RegEx:");
		GridBagConstraints gbc_lblPathRegex = new GridBagConstraints();
		gbc_lblPathRegex.anchor = GridBagConstraints.EAST;
		gbc_lblPathRegex.insets = new Insets(0, 0, 5, 5);
		gbc_lblPathRegex.gridx = 2;
		gbc_lblPathRegex.gridy = 3;
		add(lblPathRegex, gbc_lblPathRegex);

		pathRegExOption = new JComboBox();
		pathRegExOption.setModel(new DefaultComboBoxModel(scopeOptions2.values()));
		GridBagConstraints gbc_pathRegexOption = new GridBagConstraints();
		gbc_pathRegexOption.anchor = GridBagConstraints.WEST;
		gbc_pathRegexOption.insets = new Insets(0, 0, 5, 5);
		gbc_pathRegexOption.gridx = 3;
		gbc_pathRegexOption.gridy = 3;
		add(pathRegExOption, gbc_pathRegexOption);


		pathRegEx = new JTextField();
		GridBagConstraints gbc_pathRegEx = new GridBagConstraints();
		gbc_pathRegEx.insets = new Insets(0, 0, 5, 5);
		gbc_pathRegEx.fill = GridBagConstraints.HORIZONTAL;
		gbc_pathRegEx.gridx = 4;
		gbc_pathRegEx.gridy = 3;
		add(pathRegEx, gbc_pathRegEx);
		pathRegEx.setColumns(10);

		JLabel lblHeaderRegex = new JLabel("Headers RegEx:");
		GridBagConstraints gbc_lblHeaderRegex = new GridBagConstraints();
		gbc_lblHeaderRegex.anchor = GridBagConstraints.EAST;
		gbc_lblHeaderRegex.insets = new Insets(0, 0, 5, 5);
		gbc_lblHeaderRegex.gridx = 2;
		gbc_lblHeaderRegex.gridy = 4;
		add(lblHeaderRegex, gbc_lblHeaderRegex);

		headerRegExOption = new JComboBox();
		headerRegExOption.setModel(new DefaultComboBoxModel(scopeOptions2.values()));
		GridBagConstraints gbc_headerRegExOption = new GridBagConstraints();
		gbc_headerRegExOption.anchor = GridBagConstraints.WEST;
		gbc_headerRegExOption.insets = new Insets(0, 0, 5, 5);
		gbc_headerRegExOption.gridx = 3;
		gbc_headerRegExOption.gridy = 4;
		add(headerRegExOption, gbc_headerRegExOption);

		headerRegEx = new JTextField();
		GridBagConstraints gbc_headerRegEx = new GridBagConstraints();
		gbc_headerRegEx.insets = new Insets(0, 0, 5, 5);
		gbc_headerRegEx.fill = GridBagConstraints.HORIZONTAL;
		gbc_headerRegEx.gridx = 4;
		gbc_headerRegEx.gridy = 4;
		add(headerRegEx, gbc_headerRegEx);
		headerRegEx.setColumns(10);

		JLabel lblActiveIn = new JLabel("Rules active in:");
		GridBagConstraints gbc_lblActiveIn = new GridBagConstraints();
		gbc_lblActiveIn.anchor = GridBagConstraints.EAST;
		gbc_lblActiveIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblActiveIn.gridx = 2;
		gbc_lblActiveIn.gridy = 6;
		add(lblActiveIn, gbc_lblActiveIn);

		chckbxAllTools = new JCheckBox("All Tools");
		GridBagConstraints gbc_chckbxAllTools = new GridBagConstraints();
		gbc_chckbxAllTools.anchor = GridBagConstraints.WEST;
		gbc_chckbxAllTools.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxAllTools.gridx = 3;
		gbc_chckbxAllTools.gridy = 6;
		add(chckbxAllTools, gbc_chckbxAllTools);

		chckbxProxy = new JCheckBox("Proxy");
		GridBagConstraints gbc_chckbxProxy = new GridBagConstraints();
		gbc_chckbxProxy.anchor = GridBagConstraints.WEST;
		gbc_chckbxProxy.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxProxy.gridx = 3;
		gbc_chckbxProxy.gridy = 7;
		add(chckbxProxy, gbc_chckbxProxy);

		chckbxScanner = new JCheckBox("Scanner");
		GridBagConstraints gbc_chckbxScanner = new GridBagConstraints();
		gbc_chckbxScanner.anchor = GridBagConstraints.WEST;
		gbc_chckbxScanner.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxScanner.gridx = 3;
		gbc_chckbxScanner.gridy = 8;
		add(chckbxScanner, gbc_chckbxScanner);

		chckbxIntruder = new JCheckBox("Intruder");
		GridBagConstraints gbc_chckbxIntruder = new GridBagConstraints();
		gbc_chckbxIntruder.anchor = GridBagConstraints.WEST;
		gbc_chckbxIntruder.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIntruder.gridx = 3;
		gbc_chckbxIntruder.gridy = 9;
		add(chckbxIntruder, gbc_chckbxIntruder);

		chckbxRepeator = new JCheckBox("Repeator");
		GridBagConstraints gbc_chckbxRepeator = new GridBagConstraints();
		gbc_chckbxRepeator.anchor = GridBagConstraints.WEST;
		gbc_chckbxRepeator.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxRepeator.gridx = 3;
		gbc_chckbxRepeator.gridy = 10;
		add(chckbxRepeator, gbc_chckbxRepeator);

		chckbxExtender = new JCheckBox("Extender");
		GridBagConstraints gbc_chckbxExtender = new GridBagConstraints();
		gbc_chckbxExtender.anchor = GridBagConstraints.WEST;
		gbc_chckbxExtender.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxExtender.gridx = 3;
		gbc_chckbxExtender.gridy = 11;
		add(chckbxExtender, gbc_chckbxExtender);

		chckbxTarget = new JCheckBox("Target");
		GridBagConstraints gbc_chckbxTarget = new GridBagConstraints();
		gbc_chckbxTarget.anchor = GridBagConstraints.WEST;
		gbc_chckbxTarget.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxTarget.gridx = 3;
		gbc_chckbxTarget.gridy = 12;
		add(chckbxTarget, gbc_chckbxTarget);

		chckbxSequencer = new JCheckBox("Sequencer");
		GridBagConstraints gbc_chckbxSequencer = new GridBagConstraints();
		gbc_chckbxSequencer.anchor = GridBagConstraints.WEST;
		gbc_chckbxSequencer.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSequencer.gridx = 3;
		gbc_chckbxSequencer.gridy = 13;
		add(chckbxSequencer, gbc_chckbxSequencer);

		chckbxSpider = new JCheckBox("Spider");
		GridBagConstraints gbc_chckbxSpider = new GridBagConstraints();
		gbc_chckbxSpider.anchor = GridBagConstraints.WEST;
		gbc_chckbxSpider.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSpider.gridx = 3;
		gbc_chckbxSpider.gridy = 14;
		add(chckbxSpider, gbc_chckbxSpider);

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
		if(pathRegExOption.getSelectedIndex()==1) {
			pathRegEx.setEnabled(false);
		}else {
			pathRegEx.setEnabled(true);
		}

		if(headerRegExOption.getSelectedIndex()==1) {
			headerRegEx.setEnabled(false);
		}else {
			headerRegEx.setEnabled(true);
		}

		if(chckbxAllTools.isSelected()) {
			chckbxAllTools.setEnabled(true);
			chckbxProxy.setEnabled(false);
			chckbxScanner.setEnabled(false);
			chckbxIntruder.setEnabled(false);
			chckbxRepeator.setEnabled(false);
			chckbxExtender.setEnabled(false);
			chckbxTarget.setEnabled(false);
			chckbxSequencer.setEnabled(false);
			chckbxSpider.setEnabled(false);
		}else {
			chckbxAllTools.setEnabled(true);
			chckbxProxy.setEnabled(true);
			chckbxScanner.setEnabled(true);
			chckbxIntruder.setEnabled(true);
			chckbxRepeator.setEnabled(true);
			chckbxExtender.setEnabled(true);
			chckbxTarget.setEnabled(true);
			chckbxSequencer.setEnabled(true);
			chckbxSpider.setEnabled(true);
		}
		
		if(targetScopeOption.getSelectedItem().equals(scopeOptions2.DISABLED) && 
				pathRegExOption.getSelectedItem().equals(scopeOptions2.DISABLED) && 
				headerRegExOption.getSelectedItem().equals(scopeOptions2.DISABLED)) {
			// totally disabled!
			chckbxAllTools.setEnabled(false);
			chckbxProxy.setEnabled(false);
			chckbxScanner.setEnabled(false);
			chckbxIntruder.setEnabled(false);
			chckbxRepeator.setEnabled(false);
			chckbxExtender.setEnabled(false);
			chckbxTarget.setEnabled(false);
			chckbxSequencer.setEnabled(false);
			chckbxSpider.setEnabled(false);
		}
		
	}

	private void setActions() {
		setActionsJComboBoxHelper(targetScopeOption);
		setActionsJComboBoxHelper(pathRegExOption);
		setActionsJTextFieldHelper(pathRegEx);
		setActionsJComboBoxHelper(headerRegExOption);
		setActionsJTextFieldHelper(headerRegEx);
		setActionsJCheckBoxHelper(chckbxAllTools);
		setActionsJCheckBoxHelper(chckbxProxy);
		setActionsJCheckBoxHelper(chckbxScanner);
		setActionsJCheckBoxHelper(chckbxIntruder);
		setActionsJCheckBoxHelper(chckbxRepeator);
		setActionsJCheckBoxHelper(chckbxExtender);
		setActionsJCheckBoxHelper(chckbxTarget);
		setActionsJCheckBoxHelper(chckbxSequencer);
		setActionsJCheckBoxHelper(chckbxSpider);
	}
	
	private void setActionsJCheckBoxHelper(JCheckBox checkbox) {
		checkbox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				updateUIState();
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
				updateUIState();
				saveSettings();
			}
			@Override
			public void insertUpdate(DocumentEvent arg0) {
				updateUIState();
				saveSettings();
			}
			@Override
			public void removeUpdate(DocumentEvent arg0) {
				updateUIState();
				saveSettings();
			}
			});
	}
	
	private void loadSettings() {
		targetScopeOption.setSelectedIndex((int) loadExtensionSettingHelper("targetScopeOption","int",0));
		pathRegExOption.setSelectedIndex((int) loadExtensionSettingHelper("pathRegExOption","int",0));
		pathRegEx.setText((String) loadExtensionSettingHelper("pathRegEx","string",""));
		headerRegExOption.setSelectedIndex((int) loadExtensionSettingHelper("headerRegExOption","int",0));
		headerRegEx.setText((String) loadExtensionSettingHelper("headerRegEx","string","x\\-my\\-http\\-smuggler: active"));
		chckbxAllTools.setSelected((boolean) loadExtensionSettingHelper("chckbxAllTools","bool",false));
		chckbxProxy.setSelected((boolean) loadExtensionSettingHelper("chckbxProxy","bool",false));
		chckbxScanner.setSelected((boolean) loadExtensionSettingHelper("chckbxScanner","bool",false));
		chckbxIntruder.setSelected((boolean) loadExtensionSettingHelper("chckbxIntruder","bool",false));
		chckbxRepeator.setSelected((boolean) loadExtensionSettingHelper("chckbxRepeator","bool",true));
		chckbxExtender.setSelected((boolean) loadExtensionSettingHelper("chckbxExtender","bool",false));
		chckbxTarget.setSelected((boolean) loadExtensionSettingHelper("chckbxTarget","bool",false));
		chckbxSequencer.setSelected((boolean) loadExtensionSettingHelper("chckbxSequencer","bool",false));
		chckbxSpider.setSelected((boolean) loadExtensionSettingHelper("chckbxSpider","bool",false));
	}

	private void saveSettings() {
		saveExtensionSettingHelper("targetScopeOption", targetScopeOption.getSelectedIndex());
		saveExtensionSettingHelper("pathRegExOption", pathRegExOption.getSelectedIndex());
		saveExtensionSettingHelper("pathRegEx", pathRegEx.getText());
		saveExtensionSettingHelper("headerRegExOption", headerRegExOption.getSelectedIndex());
		saveExtensionSettingHelper("headerRegEx", headerRegEx.getText());
		saveExtensionSettingHelper("chckbxAllTools", chckbxAllTools.isSelected());
		saveExtensionSettingHelper("chckbxProxy", chckbxProxy.isSelected());
		saveExtensionSettingHelper("chckbxScanner", chckbxScanner.isSelected());
		saveExtensionSettingHelper("chckbxIntruder", chckbxIntruder.isSelected());
		saveExtensionSettingHelper("chckbxRepeator", chckbxRepeator.isSelected());
		saveExtensionSettingHelper("chckbxExtender", chckbxExtender.isSelected());
		saveExtensionSettingHelper("chckbxTarget", chckbxTarget.isSelected());
		saveExtensionSettingHelper("chckbxSequencer", chckbxSequencer.isSelected());
		saveExtensionSettingHelper("chckbxSpider", chckbxSpider.isSelected());	
	}
	
	private void resetSettings() {
		saveExtensionSettingHelper("targetScopeOption", 0);
		saveExtensionSettingHelper("pathRegExOption", 0);
		saveExtensionSettingHelper("pathRegEx", "");
		saveExtensionSettingHelper("headerRegExOption", 0);
		saveExtensionSettingHelper("headerRegEx", "x\\-my\\-http\\-smuggler: active");
		saveExtensionSettingHelper("chckbxAllTools", false);
		saveExtensionSettingHelper("chckbxProxy", false);
		saveExtensionSettingHelper("chckbxScanner", false);
		saveExtensionSettingHelper("chckbxIntruder", false);
		saveExtensionSettingHelper("chckbxRepeator", true);
		saveExtensionSettingHelper("chckbxExtender", false);
		saveExtensionSettingHelper("chckbxTarget", false);
		saveExtensionSettingHelper("chckbxSequencer", false);
		saveExtensionSettingHelper("chckbxSpider", false);	
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
}
