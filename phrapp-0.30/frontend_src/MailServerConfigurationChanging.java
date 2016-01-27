import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.util.regex.*;
import javax.swing.border.*;

import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

import org.jdesktop.swingx.*;
import org.jdesktop.swingx.treetable.*;

import org.apache.commons.lang3.*;

class MailServerConfigurationChanging extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1473582225865921454L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean change_mail_server_configuration(String mail_server_url, String authority_email_address, String authority_email_passwd);

	// Variables
	private JPanel         main_panel                                   = new JPanel();
	private JTextField     mail_server_url_textfield                    = new JTextField(TEXTFIELD_LENGTH);
	private JTextField     authority_email_address_textfield            = new JTextField(TEXTFIELD_LENGTH);
	private JCheckBox      authority_email_passwd_changing_checkbox     = new JCheckBox("Change an e-mail password", false);
	private JPasswordField new_authority_email_passwd_textfield         = new JPasswordField(TEXTFIELD_LENGTH);
	private JPasswordField confirm_new_authority_email_passwd_textfield = new JPasswordField(TEXTFIELD_LENGTH);
	private JPasswordField passwd_textfield                             = new JPasswordField(TEXTFIELD_LENGTH);

	private JButton        change_button	                            = new JButton("Change");
	private JButton        cancel_button                                = new JButton("Cancel");

	private String         current_mail_server_url;
	private String         current_authority_email_address;
	private String         current_authority_email_passwd;
	private String         passwd_cmp;

	// Return variable
	private boolean        result_flag;
	private String 		   m_result_msg;

	// WEB
	private String 		   m_confirm_authority_email_passwds;
	private	String 		   m_mail_server_url;
	private String 		   m_authority_email_address;
	private	String 		   m_authority_email_passwd;
	private String 		   m_admin_passwd ;
	private boolean 	   m_changepwd;

	public MailServerConfigurationChanging(Component parent, String mail_server_url, String authority_email_address, String authority_email_passwd, String passwd)
	{
		result_flag                     = false;
		current_mail_server_url         = mail_server_url;
		current_authority_email_address = authority_email_address;
		current_authority_email_passwd  = authority_email_passwd;
		passwd_cmp                      = passwd;

		init_ui(parent);
		init_mail_server_textfields(mail_server_url, authority_email_address);
		setup_actions();
	}

	// WEB
	public MailServerConfigurationChanging(String mail_server_url, String authority_email_address, String authority_email_passwd, String passwd)
	{
		result_flag                     = false;
		current_mail_server_url         = mail_server_url;
		current_authority_email_address = authority_email_address;
		current_authority_email_passwd  = authority_email_passwd;
		passwd_cmp                      = passwd;

	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel mail_server_url_label                    = new JLabel("Mail server url: ", JLabel.RIGHT);
		JLabel authority_email_address_label            = new JLabel("Authority's e-mail address: ", JLabel.RIGHT);
		JLabel new_authority_email_passwd_label         = new JLabel("New e-mail password: ", JLabel.RIGHT);
		JLabel confirm_new_authority_email_passwd_label = new JLabel("Confirm new e-mail password: ", JLabel.RIGHT);
		JLabel passwd_label                             = new JLabel("Admin's password: ", JLabel.RIGHT);

		authority_email_passwd_changing_checkbox.setFocusable(false);
		authority_email_passwd_changing_checkbox.setAlignmentX(0.0f);

		new_authority_email_passwd_textfield.setEnabled(false);
		confirm_new_authority_email_passwd_textfield.setEnabled(false);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(mail_server_url_label);
		upper_inner_panel.add(mail_server_url_textfield);
		upper_inner_panel.add(authority_email_address_label);
		upper_inner_panel.add(authority_email_address_textfield);
		upper_inner_panel.add(authority_email_passwd_changing_checkbox);
		upper_inner_panel.add(new JLabel(""));
		upper_inner_panel.add(new_authority_email_passwd_label);
		upper_inner_panel.add(new_authority_email_passwd_textfield);
		upper_inner_panel.add(confirm_new_authority_email_passwd_label);
		upper_inner_panel.add(confirm_new_authority_email_passwd_textfield);
		upper_inner_panel.add(passwd_label);
		upper_inner_panel.add(passwd_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 6, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(500, 230));
		upper_outer_panel.setMaximumSize(new Dimension(500, 230));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Buttons
		change_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(500, 30));
		buttons_panel.setMaximumSize(new Dimension(500, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(change_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(upper_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		setTitle("Mail Server Configuration Changing");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private void init_mail_server_textfields(String mail_server_url, String authority_email_address)
	{
		mail_server_url_textfield.setText(mail_server_url);
		authority_email_address_textfield.setText(authority_email_address);
	}

	private final void setup_actions()
	{
		// Authority email passwd changing checkbox
		authority_email_passwd_changing_checkbox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					new_authority_email_passwd_textfield.setEnabled(true);
					confirm_new_authority_email_passwd_textfield.setEnabled(true);
				}
				else
				{
					new_authority_email_passwd_textfield.setEnabled(false);
					confirm_new_authority_email_passwd_textfield.setEnabled(false);
				}
			}
		});

		// Change button
		change_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						change_button.setEnabled(false);
						cancel_button.setEnabled(false);

						if(validate_input())
						{
							String mail_server_url         = get_updated_mail_server_url();
							String authority_email_address = get_updated_authority_email_address();
							String authority_email_passwd  = get_updated_authority_email_passwd();

							// Call to C function
							if(change_mail_server_configuration(mail_server_url, authority_email_address, authority_email_passwd))
							{
								result_flag = true;
								dispose();
							}
						}

						change_button.setEnabled(true);
						cancel_button.setEnabled(true);
		    			}
				});
			}
		});

		// Cancel button
		cancel_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						change_button.setEnabled(false);
						cancel_button.setEnabled(false);
		        			dispose();
					}
				});
		    	}
		});
	}

	public void change(String mail_server_url, String authority_email_address, String authority_email_passwd, 
		String  confirm_authority_email_passwd, String admin_passwd, Boolean changepwd){
		m_mail_server_url         			= mail_server_url;
		m_authority_email_address 			= authority_email_address;
		m_authority_email_passwd  			= authority_email_passwd;
		m_confirm_authority_email_passwds	= confirm_authority_email_passwd;
		m_admin_passwd			  			= admin_passwd;
		m_changepwd							= changepwd.booleanValue() ;

		if(validate_input())
		{
			// Call to C function
			if(!changepwd){
				m_authority_email_passwd = current_authority_email_passwd;
			}

			if(change_mail_server_configuration(mail_server_url, authority_email_address, authority_email_passwd))
			{
				m_result_msg = "Change mail server success";
				result_flag = true;	
			}
		}
	}

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;
		String  mail_server_url         = m_mail_server_url;
		String  authority_email_address = m_authority_email_address;
		String  passwd                  = m_admin_passwd;

		// Validate mail server url
		p = Pattern.compile("^smtp://([-a-zA-Z0-9_](.[-a-zA-Z0-9_]+)*){1}(:){1}([0-9]){1,5}$");

		m = p.matcher(mail_server_url);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the Mail server url");
			m_result_msg = "Please input correct format for the Mail server url";
			return false;
		}

		int port_number = Integer.parseInt(mail_server_url.substring(mail_server_url.lastIndexOf(":") + 1));
		if(port_number < 0 || port_number > 65535)
		{
			// JOptionPane.showMessageDialog(this, "Port number must be in range between 0 and 65535");
			m_result_msg = "Port number must be in range between 0 and 65535";
			return false;
		}

		// Validate authority's e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(authority_email_address);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the authority's e-mail address");
			m_result_msg = "Please input correct format for the authority's e-mail address";
			return false;
		}

		if(m_changepwd)
		{
			String new_authority_email_passwd         = m_authority_email_passwd;
			String confirm_new_authority_email_passwd = m_confirm_authority_email_passwds;

			// Validate new authority's e-mail password
			if(!(new_authority_email_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && new_authority_email_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
			{
				// JOptionPane.showMessageDialog(this, "Please input a length of the new authority's e-mail password between " + 
				//	PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");
				m_result_msg = "Please input a length of the new authority's e-mail password between " + 
					PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters";
				return false;
			}

			p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
			m = p.matcher(new_authority_email_passwd);
			if(m.matches() == false)
			{
				// JOptionPane.showMessageDialog(this, "Please input correct format for the new authority's e-mail password");
				m_result_msg = "Please input correct format for the new authority's e-mail password";
				return false;
			}

			// Validate confirm new authority's e-mail password
			if(!(confirm_new_authority_email_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && 
				confirm_new_authority_email_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
			{
				// JOptionPane.showMessageDialog(this, "Please input a length of the confirm new authority's e-mail password between " + 
				// 	PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");
				m_result_msg = "Please input a length of the confirm new authority's e-mail password between " + 
					PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters";
				return false;
			}

			p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
			m = p.matcher(confirm_new_authority_email_passwd);
			if(m.matches() == false)
			{
				// JOptionPane.showMessageDialog(this, "Please input correct format for the confirm new authority's e-mail password");
				m_result_msg = "Please input correct format for the confirm new authority's e-mail password";
				return false;
			}

			// Do a new authority's e-mail password and a confirm new authority's e-mail password match?
			if(!new_authority_email_passwd.equals(confirm_new_authority_email_passwd))
			{
				// JOptionPane.showMessageDialog(this, "The new authority's e-mail password and confirm new authority's e-mail password do not match");
				m_result_msg = "The new authority's e-mail password and confirm new authority's e-mail password do not match";
				return false;
			}

			// Check update
			if(current_authority_email_passwd.equals(new_authority_email_passwd))
			{
				// JOptionPane.showMessageDialog(this, "No update for the authority's e-mail password");
				m_result_msg = "No update for the authority's e-mail password";
				return false;
			}
		}

		// Check update
		if(!m_changepwd && mail_server_url.equals(current_mail_server_url) && 
			authority_email_address.equals(current_authority_email_address))
		{
			// JOptionPane.showMessageDialog(this, "No any update");
			m_result_msg = "No any update";
			return false;
		}

		// Validate passwd
		if(!(passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			// JOptionPane.showMessageDialog(this, "Please input the admin password's length between " + 
			//	PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");
			m_result_msg = "Please input the admin password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters";
			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(passwd);
		if(m.matches() == false)
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the admin's password");
			m_result_msg = "Please input correct format for the admin's password";
			return false;
		}

		// Do a password match a current password?
		if(!passwd.equals(passwd_cmp))
		{
			// JOptionPane.showMessageDialog(this, "Invalid the admin's password");
			m_result_msg = "Invalid the admin's password";
			return false;
		}

		return true;
	}

	public boolean get_result()
	{
		return result_flag;
	}

	public boolean getResultFlag()
	{
		return result_flag;
	}

	public String getResultMsg()
	{
		return m_result_msg;
	}

	// public String get_updated_mail_server_url()
	// {
	// 	return mail_server_url_textfield.getText();
	// }

	// public String get_updated_authority_email_address()
	// {
	// 	return authority_email_address_textfield.getText();
	// }

	// public String get_updated_authority_email_passwd()
	// {
	// 	if(authority_email_passwd_changing_checkbox.isSelected())
	// 		return new String(new_authority_email_passwd_textfield.getPassword());
	// 	else
	// 		return current_authority_email_passwd;
	// }

	public String get_updated_mail_server_url()
	{
		return m_mail_server_url;
	}

	public String get_updated_authority_email_address()
	{
		return m_authority_email_address;
	}

	public String get_updated_authority_email_passwd()
	{
		if(authority_email_passwd_changing_checkbox.isSelected())
			return new String(new_authority_email_passwd_textfield.getPassword());
		else
			return current_authority_email_passwd;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		// JOptionPane.showMessageDialog(main_panel, alert_msg);
		if(alert_msg.equals("Sending an e-mail failed (SSL connect error)"))
			result_flag = true;
		m_result_msg = alert_msg;
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Call to C function
		uninit_backend();

		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}
}



