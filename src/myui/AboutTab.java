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

import javax.swing.ImageIcon;
import javax.swing.JPanel;

import burp.IBurpExtenderCallbacks;

import java.awt.GridBagLayout;
import javax.swing.JLabel;
import java.awt.Desktop;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class AboutTab extends JPanel {

	private final burp.IBurpExtenderCallbacks callbacks;
	private final PrintWriter stdout;
	private final PrintWriter stderr;

	/**
	 * Create the panel.
	 */
	public AboutTab(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
		this.callbacks = callbacks;
		this.stdout = stdout;
		this.stderr = stderr;

		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 86, 80, 248, 0};
		gridBagLayout.rowHeights = new int[]{0, 38, 0, 0, 0, 43, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);

		ClassLoader cldr = this.getClass().getClassLoader();
		java.net.URL imageURLMain   = cldr.getResource("resources/AboutMain.png");
		ImageIcon imageIconMain = new ImageIcon(imageURLMain);
		JLabel lblMain = new JLabel("Main"); // to see the label in eclipse design tab!
		if("running".equals("running")) // to see the image while running it.
			lblMain = new JLabel(imageIconMain);
		GridBagConstraints gbc_lblMain = new GridBagConstraints();
		gbc_lblMain.gridheight = 8;
		gbc_lblMain.insets = new Insets(0, 0, 0, 5);
		gbc_lblMain.gridx = 1;
		gbc_lblMain.gridy = 1;
		add(lblMain, gbc_lblMain);

		JLabel lblName = new JLabel("Name");
		GridBagConstraints gbc_lblName = new GridBagConstraints();
		gbc_lblName.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblName.insets = new Insets(0, 0, 5, 5);
		gbc_lblName.gridx = 2;
		gbc_lblName.gridy = 1;
		add(lblName, gbc_lblName);

		JLabel lblDynamicname = new JLabel("dynamic_name");
		GridBagConstraints gbc_lblDynamicname = new GridBagConstraints();
		gbc_lblDynamicname.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblDynamicname.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicname.gridx = 3;
		gbc_lblDynamicname.gridy = 1;
		add(lblDynamicname, gbc_lblDynamicname);

		JLabel lblVersion = new JLabel("Version");
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.insets = new Insets(0, 0, 5, 5);
		gbc_lblVersion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblVersion.gridx = 2;
		gbc_lblVersion.gridy = 2;
		add(lblVersion, gbc_lblVersion);

		JLabel lblDynamicversion = new JLabel("dynamic_version");
		GridBagConstraints gbc_lblDynamicversion = new GridBagConstraints();
		gbc_lblDynamicversion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicversion.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicversion.gridx = 3;
		gbc_lblDynamicversion.gridy = 2;
		add(lblDynamicversion, gbc_lblDynamicversion);

		JLabel lblSource = new JLabel("Source");
		GridBagConstraints gbc_lblSource = new GridBagConstraints();
		gbc_lblSource.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblSource.insets = new Insets(0, 0, 5, 5);
		gbc_lblSource.gridx = 2;
		gbc_lblSource.gridy = 3;
		add(lblSource, gbc_lblSource);

		JLabel lblDynamicsource = new JLabel("dynamic_source");
		GridBagConstraints gbc_lblDynamicsource = new GridBagConstraints();
		gbc_lblDynamicsource.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicsource.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicsource.gridx = 3;
		gbc_lblDynamicsource.gridy = 3;
		add(lblDynamicsource, gbc_lblDynamicsource);

		JLabel lblAuthor = new JLabel("Author");
		GridBagConstraints gbc_lblAuthor = new GridBagConstraints();
		gbc_lblAuthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblAuthor.insets = new Insets(0, 0, 5, 5);
		gbc_lblAuthor.gridx = 2;
		gbc_lblAuthor.gridy = 4;
		add(lblAuthor, gbc_lblAuthor);

		JLabel lblDynamicauthor = new JLabel("dynamic_author");
		GridBagConstraints gbc_lblDynamicauthor = new GridBagConstraints();
		gbc_lblDynamicauthor.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicauthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicauthor.gridx = 3;
		gbc_lblDynamicauthor.gridy = 4;
		add(lblDynamicauthor, gbc_lblDynamicauthor);

		JLabel label = new JLabel("          ");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 2;
		gbc_label.gridy = 5;
		add(label, gbc_label);

		JButton btnOpenExtensionHome = new JButton("Open extension homepage");
		btnOpenExtensionHome.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage("https://github.com/nccgroup/BurpSuiteHTTPSmuggler");
			}
		});
		GridBagConstraints gbc_btnOpenExtensionHome = new GridBagConstraints();
		gbc_btnOpenExtensionHome.insets = new Insets(0, 0, 5, 0);
		gbc_btnOpenExtensionHome.gridwidth = 2;
		gbc_btnOpenExtensionHome.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnOpenExtensionHome.gridx = 2;
		gbc_btnOpenExtensionHome.gridy = 6;
		add(btnOpenExtensionHome, gbc_btnOpenExtensionHome);

		JButton btnReportAnIssue = new JButton("Report a bug/feature!");
		btnReportAnIssue.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				openWebpage("https://github.com/nccgroup/BurpSuiteHTTPSmuggler/issues");
			}
		});
		GridBagConstraints gbc_btnReportAnIssue = new GridBagConstraints();
		gbc_btnReportAnIssue.insets = new Insets(0, 0, 5, 0);
		gbc_btnReportAnIssue.anchor = GridBagConstraints.WEST;
		gbc_btnReportAnIssue.gridwidth = 2;
		gbc_btnReportAnIssue.gridx = 2;
		gbc_btnReportAnIssue.gridy = 7;
		add(btnReportAnIssue, gbc_btnReportAnIssue);
		
		lblDynamicname.setText("Burp Suite HTTP Smuggler");
		lblDynamicversion.setText(String.valueOf(0.1));
		lblDynamicsource.setText("https://github.com/nccgroup/BurpSuiteHTTPSmuggler/");
		lblDynamicauthor.setText("Soroush Dalili from NCC Group");
		
	}

	private static void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static void openWebpage(String url) {
		try {
			openWebpage((new URL(url)).toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}


}
