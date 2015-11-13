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

class ServerAddressesConfigurationChanging extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1433582225865921454L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean change_server_addresses_configuration(String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr);

	// Variables
	private JPanel         main_panel                         = new JPanel();
	private JTextField     audit_server_ip_addr_textfield     = new JTextField(TEXTFIELD_LENGTH);
	private JTextField     phr_server_ip_addr_textfield       = new JTextField(TEXTFIELD_LENGTH);
	private JTextField     emergency_server_ip_addr_textfield = new JTextField(TEXTFIELD_LENGTH);
	private JPasswordField passwd_textfield                   = new JPasswordField(TEXTFIELD_LENGTH);

	private JButton        change_button	                  = new JButton("Change");
	private JButton        cancel_button                      = new JButton("Cancel");

	private String         current_audit_server_ip_addr;
	private String         current_phr_server_ip_addr;
	private String         current_emergency_server_ip_addr;
	private String         passwd_cmp;


	// Web
	private	String			m_audit_server_ip_addr     ;
	private	String 			m_phr_server_ip_addr       ;
	private	String 			m_emergency_server_ip_addr ;
	private String 			m_passwd				   ;


	// Return variable
	private boolean        result_flag;

	public ServerAddressesConfigurationChanging(Component parent, String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr, String passwd)
	{
		result_flag                      = false;
		current_audit_server_ip_addr     = audit_server_ip_addr;
		current_phr_server_ip_addr       = phr_server_ip_addr;
		current_emergency_server_ip_addr = emergency_server_ip_addr;
		passwd_cmp                       = passwd;

		init_ui(parent);
		init_server_address_textfields(audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr);
		setup_actions();
	}

	public ServerAddressesConfigurationChanging(String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr, String passwd)
	{
		result_flag                      = false;
		current_audit_server_ip_addr     = audit_server_ip_addr;
		current_phr_server_ip_addr       = phr_server_ip_addr;
		current_emergency_server_ip_addr = emergency_server_ip_addr;
		passwd_cmp                       = passwd;
	}


	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel audit_server_ip_addr_label     = new JLabel("Audit server's IP address: ", JLabel.RIGHT);
		JLabel phr_server_ip_addr_label       = new JLabel("PHR server's IP address: ", JLabel.RIGHT);
		JLabel emergency_server_ip_addr_label = new JLabel("Emergency server's IP address: ", JLabel.RIGHT);
		JLabel passwd_label                   = new JLabel("Admin's password: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(audit_server_ip_addr_label);
		upper_inner_panel.add(audit_server_ip_addr_textfield);
		upper_inner_panel.add(phr_server_ip_addr_label);
		upper_inner_panel.add(phr_server_ip_addr_textfield);
		upper_inner_panel.add(emergency_server_ip_addr_label);
		upper_inner_panel.add(emergency_server_ip_addr_textfield);
		upper_inner_panel.add(passwd_label);
		upper_inner_panel.add(passwd_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 4, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(420, 153));
		upper_outer_panel.setMaximumSize(new Dimension(420, 153));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Buttons
		change_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(420, 30));
		buttons_panel.setMaximumSize(new Dimension(420, 30));
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

		setTitle("Server Addresses Configuration Changing");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private void init_server_address_textfields(String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr)
	{
		audit_server_ip_addr_textfield.setText(audit_server_ip_addr);
		phr_server_ip_addr_textfield.setText(phr_server_ip_addr);
		emergency_server_ip_addr_textfield.setText(emergency_server_ip_addr);
	}

	public void change(String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr, String passwd){

		m_audit_server_ip_addr     = audit_server_ip_addr;
		m_phr_server_ip_addr       = phr_server_ip_addr;
		m_emergency_server_ip_addr = emergency_server_ip_addr;
		m_passwd				   = passwd;


		if(validate_input())
		{
			// Call to C function
			if(change_server_addresses_configuration(audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr))
			{
				result_flag = true;
			}
		}
	}

	private final void setup_actions()
	{
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
							String audit_server_ip_addr     = get_updated_audit_server_ip_address();
							String phr_server_ip_addr       = get_updated_phr_server_ip_address();
							String emergency_server_ip_addr = get_updated_emergency_server_ip_address();

							// Call to C function
							if(change_server_addresses_configuration(audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr))
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

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;
		String  audit_server_ip_addr     = m_audit_server_ip_addr;
		String  phr_server_ip_addr       = m_phr_server_ip_addr;
		String  emergency_server_ip_addr = m_emergency_server_ip_addr;
		String  passwd                   = m_passwd;

		// Validate IP addresses
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(audit_server_ip_addr);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the Audit server's IP address");
			return false;
		}

		m = p.matcher(phr_server_ip_addr);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the PHR server's IP address");
			return false;
		}

		m = p.matcher(emergency_server_ip_addr);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the Emergency server's IP address");
			return false;
		}

		// Check update
		if(audit_server_ip_addr.equals(current_audit_server_ip_addr) && phr_server_ip_addr.equals(current_phr_server_ip_addr) 
			&& emergency_server_ip_addr.equals(current_emergency_server_ip_addr))
		{
			JOptionPane.showMessageDialog(this, "No any address update");
			return false;
		}

		// Validate passwd
		if(!(passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the admin password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the admin's password");
			return false;
		}

		// Do a password match a current password?
		if(!passwd.equals(passwd_cmp))
		{
			JOptionPane.showMessageDialog(this, "Invalid the admin's password");
			return false;
		}

		return true;
	}

	public boolean get_result()
	{
		return result_flag;
	}

	public boolean getResult()
	{
		return result_flag;
	}

	// public String get_updated_audit_server_ip_address()
	// {
	// 	return audit_server_ip_addr_textfield.getText();
	// }

	// public String get_updated_phr_server_ip_address()
	// {
	// 	return phr_server_ip_addr_textfield.getText();
	// }

	// public String get_updated_emergency_server_ip_address()
	// {
	// 	return emergency_server_ip_addr_textfield.getText();
	// }

	public String get_updated_audit_server_ip_address()
	{
		return m_audit_server_ip_addr;
	}

	public String get_updated_phr_server_ip_address()
	{
		return m_phr_server_ip_addr;
	}

	public String get_updated_emergency_server_ip_address()
	{
		return m_emergency_server_ip_addr;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		JOptionPane.showMessageDialog(main_panel, alert_msg);
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



